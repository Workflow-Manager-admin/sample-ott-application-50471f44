'use strict';

/**
 * API Gateway for OTT Platform
 * - Central entry point: REST + GraphQL, routing, load balancing (round-robin proxy), versioning, documentation (Swagger), rate-limiting, request/response normalization, validation & sanitization, authentication, caching, error handling, metrics, CORS.
 * - All major concerns are organized modularly for maintainability and extensibility.
 */

require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const { expressjwt: jwt } = require('express-jwt');
const { body, query, param, validationResult } = require('express-validator');
const mongoSanitize = require('express-mongo-sanitize');
const NodeCache = require('node-cache');
const apicache = require('apicache');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const { graphqlHTTP } = require('express-graphql');
const { makeExecutableSchema } = require('@graphql-tools/schema');
const winston = require('winston');
const promClient = require('prom-client');
const { createProxyMiddleware } = require('http-proxy-middleware');
const compression = require('compression');

const PORT = process.env.PORT || 3000;

// === Logger (Winston) ===
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(
      ({ timestamp, level, message }) => `${timestamp} ${level.toUpperCase()}: ${message}`
    )
  ),
  transports: [new winston.transports.Console()]
});

// === Metrics ===
const collectDefaultMetrics = promClient.collectDefaultMetrics;
collectDefaultMetrics();
const requestCounter = new promClient.Counter({
  name: 'api_requests_total',
  help: 'Total number of requests to the API Gateway'
});

// === Response Caching ===
const nodeCache = new NodeCache({ stdTTL: 60, checkperiod: 120 });
const cache = apicache.middleware;

// === Express App Setup ===
const app = express();
app.use(helmet());
app.use(compression());
app.use(express.json());
app.use(mongoSanitize());
app.use(cors({
  origin: '*',
  methods: 'GET,POST,PUT,DELETE,OPTIONS',
  allowedHeaders: 'Content-Type,Authorization'
}));
app.use(morgan('combined', { stream: { write: (msg) => logger.info(msg.trim()) } }));

// === Rate Limiter Middleware ===
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // Per windowMs per IP
  keyGenerator: (req, res) => req.ip,
  legacyHeaders: false,
  handler: (req, res) => {
    res.set('Retry-After', String(60));
    res.status(429).json({ error: 'Too many requests, please try again later.' });
  }
});
app.use(limiter);

// === Prometheus Metrics endpoint ===
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', promClient.register.contentType);
    res.end(await promClient.register.metrics());
  } catch (err) {
    res.status(500).end(err);
  }
});

// === Middleware: Standardized Responses ===
app.use((req, res, next) => {
  const oldJson = res.json;
  res.success = (data, status = 200) => res.status(status).json({ success: true, data });
  res.error = (error, code = 500) => res.status(code).json({ success: false, error });
  res.json = function (body) { oldJson.call(this, body); };
  next();
});

// === JWT Authentication Middleware Setup ===
const jwtSecret = process.env.JWT_SECRET || 'supersecret-key';
// Only protect /api and /graphql routes
app.use(['/api', '/graphql'], jwt({
  secret: jwtSecret,
  algorithms: ['HS256'],
  credentialsRequired: true,
}).unless({ path: [
  /^\/api\/v([0-9]+)\/auth\/.*/, // Auth endpoints
  /^\/graphql$/, // Unauthenticated queries accepted (customize as needed)
]}));

// === API Versioning Helper ===
const apiBase = '/api/v:version(1|2)';

// === Swagger/OpenAPI Documentation ===
const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'OTT Platform API Gateway',
    version: '1.0.0',
    description: 'Central API Gateway for the OTT platform, offering REST and GraphQL endpoints, with security and developer tooling.'
  },
  servers: [
    { url: `http://localhost:${PORT}`, description: 'Local server' }
  ],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT'
      }
    }
  },
  security: [{ bearerAuth: [] }]
};
const swaggerOptions = {
  swaggerDefinition,
  apis: ['./index.js'], // Use JSDoc in this file
};
const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// === Dummy Microservice Targets by Version ===
const targets = {
  v1: {
    user: process.env.SVC_USER_URI_V1 || 'http://localhost:5001',
    content: process.env.SVC_CONTENT_URI_V1 || 'http://localhost:5002',
  },
  v2: {
    user: process.env.SVC_USER_URI_V2 || 'http://localhost:6001',
    content: process.env.SVC_CONTENT_URI_V2 || 'http://localhost:6002',
  }
};
// Round-robin state per service
const roundRobinState = {
  user: 0,
  content: 0
};
// For round-robin/load-balancing proxying (simple demo version)
function selectTarget(service, version) {
  // If you have multiple targets (for load balancing), rotate over them:
  // let endpoints = [targets[version][service], ...]
  // let idx = roundRobinState[service]++ % endpoints.length;
  // return endpoints[idx];
  // Single one for demo:
  return targets[version][service];
}

// === Proxy Setup ===
function makeProxy(service) {
  return (req, res, next) => {
    const { version } = req.params;
    const target = selectTarget(service, `v${version}`);
    if (!target) return res.error(`Service ${service} (version ${version}) unavailable`, 503);

    return createProxyMiddleware({
      target,
      changeOrigin: true,
      pathRewrite: (path, req) => path.replace(apiBase + `/${service}`, ''),
      onProxyReq(proxyReq, req) {
        // propagate auth headers etc if needed
        if (req.user) {
          proxyReq.setHeader('x-auth-user', req.user.sub || req.user.id || '');
        }
      }
    })(req, res, next);
  };
}

// === Input Validation & Sanitization Example for public endpoints ===
const signupValidationRules = [
  body('email').isEmail(),
  body('password').isLength({ min: 8 }),
];
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty())
    return res.status(400).json({ errors: errors.array() });
  next();
};

// === Simple In-memory Caching for public content (NodeCache & Apicache) ===
const publicCache = cache('30 seconds'); // For demo, cache all GET 30s

// === REST Endpoints (Gateway Examples) ===

/**
 * @openapi
 * /api/v1/auth/login:
 *   post:
 *     summary: User login
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email: { type: string, format: email }
 *               password: { type: string, minLength: 8 }
 *     responses:
 *       200:
 *         description: User authenticated, returns JWT
 *       400:
 *         description: Validation error
 */
app.post(
  '/api/v1/auth/login',
  [
    body('email').isEmail(),
    body('password').isLength({ min: 8 }),
    validate
  ],
  async (req, res) => {
    // Forward request to user-service auth endpoint, or implement a mock.
    // Here we just mock JWT assignment for demo:
    const jwt = require('jsonwebtoken');
    const { email } = req.body;
    const token = jwt.sign({ sub: email }, jwtSecret, { expiresIn: '1h' });
    res.status(200).json({ token });
  }
);

/**
 * @openapi
 * /api/v1/user/*:
 *   get:
 *     summary: User microservice passthrough
 *     tags: [User]
 *     security: [{ bearerAuth: [] }]
 *     responses:
 *       200:
 *         description: User microservice response
 */
app.use(`${apiBase}/user`, makeProxy('user'));
/**
 * @openapi
 * /api/v1/content/*:
 *   get:
 *     summary: Content microservice passthrough
 *     tags: [Content]
 *     security: [{ bearerAuth: [] }]
 *     responses:
 *       200:
 *         description: Content microservice response
 */
app.use(`${apiBase}/content`, makeProxy('content'));

// === Public (cached) Content Example ===
app.get(`${apiBase}/public/content/:id`, publicCache, (req, res) => {
  // Demo: serve from cache or fake data
  const { id } = req.params;
  const cached = nodeCache.get(id);
  if (cached) return res.success(cached);

  const exampleContent = { id, title: 'Example Video', duration: 3600 };
  nodeCache.set(id, exampleContent, 30);
  res.success(exampleContent);
});

// === GraphQL Endpoint ===

/**
 * @openapi
 * /graphql:
 *   post:
 *     summary: GraphQL endpoint for aggregated data
 *     tags: [GraphQL]
 *     security: [{ bearerAuth: [] }]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               query:
 *                 type: string
 *                 description: The GraphQL query string
 *                 example: "{ user { id name } }"
 *     responses:
 *       200:
 *         description: Aggregated data response
 */

const typeDefs = `
  type User {
    id: ID!
    email: String!
  }
  type Content {
    id: ID!
    title: String
    duration: Int
  }
  type Query {
    user(id: ID!): User
    content(id: ID!): Content
  }
`;
const resolvers = {
  Query: {
    user: async (_, { id }) => {
      // Call to user microservice or implement mock
      return { id, email: 'user@email.com' };
    },
    content: async (_, { id }) => {
      // Call to content microservice or implement mock
      return { id, title: 'Example Movie', duration: 4200 };
    },
  },
};
const schema = makeExecutableSchema({ typeDefs, resolvers });
app.use('/graphql', graphqlHTTP({
  schema,
  graphiql: true,
  customFormatErrorFn: (err) => ({
    message: err.message,
    locations: err.locations,
    path: err.path,
    extensions: err.extensions,
  })
}));

// === 404 Catch-all ===
app.use((req, res, next) => {
  res.status(404).json({ error: 'Resource not found' });
});

// === Error Handling Middleware ===
app.use((err, req, res, next) => {
  logger.error(`Error: ${err.stack || err.toString()}`);
  // JWT Unauthorized error
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ error: 'Invalid or missing token' });
  }
  // Express-validator
  if (err.array) {
    return res.status(400).json({ errors: err.array() });
  }
  res.status(500).json({ error: 'Internal server error' });
});

// === Startup & Banner ===
app.listen(PORT, () => {
  logger.info(`API Gateway running on http://localhost:${PORT} (Docs: /docs, Metrics: /metrics)`);
});
