const express = require('express');
const mongoose = require('mongoose');
const pino = require('pino');
const pinoHttp = require('pino-http');
const helmet = require('helmet');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const logger = pino({ level: 'info' });
const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(pinoHttp({ logger }));

// MongoDB connection
const MONGO_URL = process.env.MONGO_URL || 'mongodb://localhost:27017/keephy_tenant_isolation';
mongoose.connect(MONGO_URL);

// Tenant Schema
const TenantSchema = new mongoose.Schema({
  tenantId: { type: String, unique: true, required: true },
  name: String,
  status: { type: String, enum: ['active', 'suspended', 'inactive'], default: 'active' },
  plan: { type: String, enum: ['free', 'basic', 'premium', 'enterprise'], default: 'free' },
  isolationLevel: { type: String, enum: ['shared', 'dedicated', 'private'], default: 'shared' },
  dataRetention: { type: Number, default: 365 }, // days
  maxUsers: { type: Number, default: 10 },
  maxSubmissions: { type: Number, default: 1000 },
  features: [String],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Tenant Resource Schema
const TenantResourceSchema = new mongoose.Schema({
  tenantId: String,
  resourceType: String,
  resourceId: String,
  permissions: [String],
  createdAt: { type: Date, default: Date.now }
});

// Data Isolation Policy Schema
const IsolationPolicySchema = new mongoose.Schema({
  tenantId: String,
  policyType: { type: String, enum: ['data', 'compute', 'network', 'storage'] },
  rules: [{
    field: String,
    operator: String,
    value: mongoose.Schema.Types.Mixed
  }],
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const Tenant = mongoose.model('Tenant', TenantSchema);
const TenantResource = mongoose.model('TenantResource', TenantResourceSchema);
const IsolationPolicy = mongoose.model('IsolationPolicy', IsolationPolicySchema);

// Middleware to extract tenant from JWT
function extractTenant(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    req.tenantId = decoded.tenantId;
    req.userId = decoded.userId;
    req.roles = decoded.roles || [];
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Routes
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'tenant-isolation-service' });
});

app.get('/ready', async (req, res) => {
  try {
    await mongoose.connection.db.admin().ping();
    res.json({ status: 'ready', service: 'tenant-isolation-service' });
  } catch (error) {
    res.status(503).json({ status: 'not ready', error: error.message });
  }
});

// Create tenant
app.post('/tenants', async (req, res) => {
  try {
    const { tenantId, name, plan, isolationLevel, maxUsers, maxSubmissions, features } = req.body;
    
    const tenant = new Tenant({
      tenantId,
      name,
      plan,
      isolationLevel,
      maxUsers,
      maxSubmissions,
      features
    });
    
    await tenant.save();
    
    // Create default isolation policies
    await createDefaultPolicies(tenantId);
    
    res.json({ tenant, message: 'Tenant created successfully' });
  } catch (error) {
    if (error.code === 11000) {
      res.status(409).json({ error: 'Tenant already exists' });
    } else {
      logger.error('Tenant creation error:', error);
      res.status(500).json({ error: 'Failed to create tenant' });
    }
  }
});

// Get tenant info
app.get('/tenants/:tenantId', extractTenant, async (req, res) => {
  try {
    const { tenantId } = req.params;
    
    // Verify tenant access
    if (req.tenantId !== tenantId && !req.roles.includes('super_admin')) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const tenant = await Tenant.findOne({ tenantId });
    if (!tenant) {
      return res.status(404).json({ error: 'Tenant not found' });
    }
    
    res.json({ tenant });
  } catch (error) {
    logger.error('Tenant fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch tenant' });
  }
});

// Update tenant
app.put('/tenants/:tenantId', extractTenant, async (req, res) => {
  try {
    const { tenantId } = req.params;
    const updates = req.body;
    
    // Verify tenant access
    if (req.tenantId !== tenantId && !req.roles.includes('super_admin')) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    updates.updatedAt = new Date();
    const tenant = await Tenant.findOneAndUpdate(
      { tenantId },
      updates,
      { new: true, runValidators: true }
    );
    
    if (!tenant) {
      return res.status(404).json({ error: 'Tenant not found' });
    }
    
    res.json({ tenant, message: 'Tenant updated successfully' });
  } catch (error) {
    logger.error('Tenant update error:', error);
    res.status(500).json({ error: 'Failed to update tenant' });
  }
});

// Get tenant resources
app.get('/tenants/:tenantId/resources', extractTenant, async (req, res) => {
  try {
    const { tenantId } = req.params;
    const { resourceType } = req.query;
    
    // Verify tenant access
    if (req.tenantId !== tenantId && !req.roles.includes('super_admin')) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const query = { tenantId };
    if (resourceType) query.resourceType = resourceType;
    
    const resources = await TenantResource.find(query);
    res.json({ resources });
  } catch (error) {
    logger.error('Resources fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch resources' });
  }
});

// Create isolation policy
app.post('/tenants/:tenantId/policies', extractTenant, async (req, res) => {
  try {
    const { tenantId } = req.params;
    const { policyType, rules } = req.body;
    
    // Verify tenant access
    if (req.tenantId !== tenantId && !req.roles.includes('super_admin')) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const policy = new IsolationPolicy({
      tenantId,
      policyType,
      rules
    });
    
    await policy.save();
    res.json({ policy, message: 'Isolation policy created' });
  } catch (error) {
    logger.error('Policy creation error:', error);
    res.status(500).json({ error: 'Failed to create policy' });
  }
});

// Get isolation policies
app.get('/tenants/:tenantId/policies', extractTenant, async (req, res) => {
  try {
    const { tenantId } = req.params;
    const { policyType } = req.query;
    
    // Verify tenant access
    if (req.tenantId !== tenantId && !req.roles.includes('super_admin')) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const query = { tenantId, isActive: true };
    if (policyType) query.policyType = policyType;
    
    const policies = await IsolationPolicy.find(query);
    res.json({ policies });
  } catch (error) {
    logger.error('Policies fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch policies' });
  }
});

// Validate data access
app.post('/validate-access', extractTenant, async (req, res) => {
  try {
    const { resourceType, resourceId, action } = req.body;
    
    // Check if resource belongs to tenant
    const resource = await TenantResource.findOne({
      tenantId: req.tenantId,
      resourceType,
      resourceId
    });
    
    if (!resource) {
      return res.status(404).json({ 
        allowed: false, 
        reason: 'Resource not found or access denied' 
      });
    }
    
    // Check permissions
    const hasPermission = resource.permissions.includes(action) || 
                         resource.permissions.includes('*');
    
    if (!hasPermission) {
      return res.status(403).json({ 
        allowed: false, 
        reason: 'Insufficient permissions' 
      });
    }
    
    res.json({ 
      allowed: true, 
      tenantId: req.tenantId,
      resource: resource
    });
  } catch (error) {
    logger.error('Access validation error:', error);
    res.status(500).json({ error: 'Failed to validate access' });
  }
});

// Helper function to create default isolation policies
async function createDefaultPolicies(tenantId) {
  const defaultPolicies = [
    {
      tenantId,
      policyType: 'data',
      rules: [
        { field: 'tenantId', operator: 'equals', value: tenantId }
      ]
    },
    {
      tenantId,
      policyType: 'compute',
      rules: [
        { field: 'maxConcurrentRequests', operator: 'less_than', value: 100 }
      ]
    }
  ];
  
  for (const policy of defaultPolicies) {
    const isolationPolicy = new IsolationPolicy(policy);
    await isolationPolicy.save();
  }
}

const PORT = process.env.PORT || 3017;
app.listen(PORT, () => {
  logger.info(`Tenant isolation service running on port ${PORT}`);
});
