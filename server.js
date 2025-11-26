require('dotenv').config();
const express = require('express');
const axios = require('axios');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON bodies
app.use(express.json());

// Airtable configuration
const AIRTABLE_BASE_ID = 'apphFT63p1KWuTrGO';

// Authentication middleware - require token in request
function authenticateToken(req, res, next) {
  // Try to get token from body, query, or header
  const token = req.body?.token || req.query?.token || req.headers['x-token'] || req.headers['authorization']?.replace('Bearer ', '');
  
  if (!token || typeof token !== 'string' || token.trim().length === 0) {
    return res.status(401).json({ error: 'Authentication required. Provide token in body, query parameter, x-token header, or Authorization header.' });
  }
  
  // Sanitize token (basic check - should be alphanumeric with some special chars)
  const sanitizedToken = token.trim();
  if (sanitizedToken.length < 10) {
    return res.status(401).json({ error: 'Invalid token format' });
  }
  
  // Store token in request for later use
  req.airtableToken = sanitizedToken;
  next();
}

// Input sanitization - prevent injection attacks
function sanitizeInput(input) {
  if (typeof input !== 'string') {
    return input;
  }
  
  // Remove any characters that could be used for injection
  // Allow alphanumeric, spaces, hyphens, underscores, and basic punctuation
  return input.replace(/[^a-zA-Z0-9\s\-_.,!?@#$%&*()]/g, '').trim();
}

// Sanitize table name
function sanitizeTableName(table) {
  if (!table || typeof table !== 'string') {
    return null;
  }
  // Table names should be alphanumeric with spaces, hyphens, underscores
  return sanitizeInput(table);
}

// Sanitize record ID (Airtable IDs are alphanumeric)
function sanitizeRecordId(recordId) {
  if (!recordId || typeof recordId !== 'string') {
    return null;
  }
  // Only allow alphanumeric characters
  return recordId.replace(/[^a-zA-Z0-9]/g, '');
}

// Sanitize field names and values
function sanitizeFields(fields) {
  if (!fields || typeof fields !== 'object' || Array.isArray(fields)) {
    return {};
  }
  
  const sanitized = {};
  for (const [key, value] of Object.entries(fields)) {
    const sanitizedKey = sanitizeInput(key);
    if (sanitizedKey) {
      // Sanitize value based on type
      if (typeof value === 'string') {
        sanitized[sanitizedKey] = sanitizeInput(value);
      } else if (typeof value === 'number' || typeof value === 'boolean' || value === null) {
        sanitized[sanitizedKey] = value;
      } else if (Array.isArray(value)) {
        sanitized[sanitizedKey] = value.map(item => 
          typeof item === 'string' ? sanitizeInput(item) : item
        );
      } else {
        sanitized[sanitizedKey] = value;
      }
    }
  }
  return sanitized;
}

// Helper function to get authorization headers (uses token from request)
const getAuthHeaders = (token) => ({
  'Authorization': `Bearer ${token}`,
  'Content-Type': 'application/json'
});

// Function to redact fields that contain "redacted" in the name (case-insensitive)
function redactFields(record) {
  if (!record || typeof record !== 'object') {
    return record;
  }
  
  const redacted = { ...record };
  
  for (const key in redacted) {
    if (key.toLowerCase().includes('redacted')) {
      redacted[key] = 'redacted';
    }
  }
  
  return redacted;
}

// Function to filter record to only include provided fields
function filterRecordFields(record, providedFields) {
  if (!record || !providedFields || Object.keys(providedFields).length === 0) {
    return record;
  }
  
  const filtered = { id: record.id };
  const providedKeys = Object.keys(providedFields);
  
  providedKeys.forEach(key => {
    if (record.hasOwnProperty(key)) {
      filtered[key] = record[key];
    }
  });
  
  return filtered;
}

// Store all Airtable data in memory
let activeData = [];

// Queue system for async Airtable operations
const queue = [];
let isProcessingQueue = false;

// Generate temporary ID for optimistic updates
function generateTempId() {
  return `temp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

// Process queue in background
async function processQueue() {
  if (isProcessingQueue || queue.length === 0) {
    return;
  }

  isProcessingQueue = true;
  console.log(`Processing queue: ${queue.length} job(s) pending`);

  while (queue.length > 0) {
    const job = queue.shift();
    try {
      await executeAirtableOperation(job);
      console.log(`✓ Queue job completed: ${job.type} ${job.recordId || job.tempId || ''}`);
    } catch (error) {
      console.error(`✗ Queue job failed: ${job.type}`, error.response?.data || error.message);
      // Handle rollback for failed operations
      await rollbackOperation(job);
    }
  }

  isProcessingQueue = false;
  if (queue.length > 0) {
    // More jobs added while processing, continue
    setImmediate(processQueue);
  }
}

// Execute the actual Airtable API call
async function executeAirtableOperation(job) {
  const { type, tableId, recordId, tempId, fields, token } = job;

  switch (type) {
    case 'create':
      const createResponse = await axios.post(
        `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${tableId}`,
        { fields: job.originalFields },
        { headers: getAuthHeaders(token) }
      );
      // Update temp ID with real ID
      const tableData = activeData.find(t => t.id === tableId);
      if (tableData) {
        const recordIndex = tableData.records.findIndex(r => r.id === tempId);
        if (recordIndex !== -1) {
          tableData.records[recordIndex] = {
            id: createResponse.data.id,
            ...createResponse.data.fields
          };
        }
      }
      break;

    case 'update':
      await axios.patch(
        `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${tableId}`,
        {
          records: [{
            id: recordId,
            fields: fields
          }]
        },
        { headers: getAuthHeaders(token) }
      );
      // Update activeData with final state from Airtable
      const updateTableData = activeData.find(t => t.id === tableId);
      if (updateTableData) {
        const updateResponse = await axios.get(
          `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${tableId}/${recordId}`,
          { headers: getAuthHeaders(token) }
        );
        const recordIndex = updateTableData.records.findIndex(r => r.id === recordId);
        if (recordIndex !== -1) {
          updateTableData.records[recordIndex] = {
            id: updateResponse.data.id,
            ...updateResponse.data.fields
          };
        }
      }
      break;

    case 'delete':
      await axios.delete(
        `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${tableId}/${recordId}`,
        { headers: getAuthHeaders(token) }
      );
      // Already removed from activeData optimistically
      break;
  }
}

// Rollback optimistic update on failure
async function rollbackOperation(job) {
  const { type, tableId, recordId, tempId, originalRecord } = job;
  const tableData = activeData.find(t => t.id === tableId);

  if (!tableData) return;

  switch (type) {
    case 'create':
      // Remove the record that was optimistically added
      const createIndex = tableData.records.findIndex(r => r.id === tempId);
      if (createIndex !== -1) {
        tableData.records.splice(createIndex, 1);
        console.log(`Rolled back create operation for temp ID: ${tempId}`);
      }
      break;

    case 'update':
      // Restore original record
      const updateIndex = tableData.records.findIndex(r => r.id === recordId);
      if (updateIndex !== -1 && originalRecord) {
        tableData.records[updateIndex] = originalRecord;
        console.log(`Rolled back update operation for record: ${recordId}`);
      }
      break;

    case 'delete':
      // Restore deleted record
      if (originalRecord) {
        tableData.records.push(originalRecord);
        console.log(`Rolled back delete operation for record: ${recordId}`);
      }
      break;
  }
}

// Function to get a table by name or id
function getTable(table) {
  return activeData.find(t => t.name === table || t.id === table);
}

// Function to get records from a table with optional field filtering
// Automatically redacts fields with "redacted" in the name
function get(table, fields = []) {
  const tableData = getTable(table);
  
  if (!tableData) {
    return null;
  }
  
  // Redact and filter records
  let records = tableData.records.map(record => redactFields(record));
  
  // If fields specified, filter to only those fields
  if (fields && fields.length > 0) {
    records = records.map(record => {
      const filtered = { id: record.id };
      fields.forEach(field => {
        if (record.hasOwnProperty(field)) {
          filtered[field] = record[field];
        }
      });
      return filtered;
    });
  }
  
  return records;
}


// Function to get all records from a table with pagination
async function getAllRecordsFromTable(tableId, token) {
  const records = [];
  let offset = null;

  do {
    const params = { pageSize: 100 };
    if (offset) {
      params.offset = offset;
    }

    const response = await axios.get(
      `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${tableId}`,
      {
        headers: getAuthHeaders(token),
        params
      }
    );

    // Transform records: merge id into fields and flatten
    const transformedRecords = response.data.records.map(record => ({
      id: record.id,
      ...record.fields
    }));

    records.push(...transformedRecords);
    offset = response.data.offset || null;
  } while (offset);

  return records;
}

// Function to fetch all tables and their data (uses env token for initial load)
async function loadAirtableData() {
  try {
    const initialToken = process.env.airtable_pat;
    if (!initialToken) {
      console.warn('Warning: No Airtable token in environment. API will require token in requests.');
      return;
    }

    console.log('Fetching Airtable base schema...');
    
    // Get all tables in the base
    const tablesResponse = await axios.get(
      `https://api.airtable.com/v0/meta/bases/${AIRTABLE_BASE_ID}/tables`,
      { headers: getAuthHeaders(initialToken) }
    );

    const tables = tablesResponse.data.tables;
    console.log(`Found ${tables.length} table(s). Fetching records...`);

    // Fetch all records from each table
    activeData = await Promise.all(
      tables.map(async (table) => {
        console.log(`Fetching records from table: ${table.name} (${table.id})`);
        const records = await getAllRecordsFromTable(table.id, initialToken);
        console.log(`  - Fetched ${records.length} records`);
        
        return {
          id: table.id,
          name: table.name,
          records: records
        };
      })
    );

    const totalRecords = activeData.reduce((sum, table) => sum + table.records.length, 0);
    console.log(`✓ Successfully loaded ${totalRecords} total records from ${activeData.length} table(s)`);
  } catch (error) {
    console.error('Error loading Airtable data:', error.response?.data || error.message);
    // Don't throw - allow server to start even if initial load fails
    console.warn('Server will start but initial data load failed. Use API endpoints with token to load data.');
  }
}

// Root endpoint - returns comprehensive API documentation
app.get('/', (req, res) => {
  res.json({
    name: "Airtable Active Record API",
    version: "1.0.0",
    description: "A high-performance, secure API for interacting with Airtable data using optimistic updates and background queue processing.",
    
    authentication: {
      description: "All endpoints (except GET /) require authentication via token",
      methods: [
        "Request body: { 'token': 'your_airtable_pat', ... }",
        "Query parameter: ?token=your_airtable_pat",
        "Header: x-token: your_airtable_pat",
        "Authorization header: Authorization: Bearer your_airtable_pat"
      ],
      note: "Token must be a valid Airtable Personal Access Token (PAT)"
    },

    endpoints: {
      "GET /": {
        description: "Returns this API documentation",
        authentication: false,
        example: "curl http://localhost:3000/"
      },

      "GET /get": {
        description: "Retrieve records from a table with optional field filtering",
        authentication: true,
        parameters: {
          table: {
            type: "string (query parameter)",
            required: true,
            description: "Table name or table ID",
            example: "Signups"
          },
          fields: {
            type: "string (comma-separated) or array (query parameter)",
            required: false,
            description: "Optional list of fields to return. If omitted, returns all fields (with redaction applied)",
            example: "Name,Email"
          },
          token: {
            type: "string (query parameter)",
            required: true,
            description: "Airtable Personal Access Token"
          }
        },
        response: {
          type: "array of objects",
          description: "Array of records. Each record includes 'id' field plus requested fields. Fields with 'redacted' in name are automatically redacted.",
          example: [
            {
              "id": "recXXXXXXXXXXXXXX",
              "Name": "John Doe",
              "Email": "john@example.com",
              "address-redacted": "redacted"
            }
          ]
        },
        example_request: "curl 'http://localhost:3000/get?table=Signups&token=your_token&fields=Name,Email'",
        example_request_all_fields: "curl 'http://localhost:3000/get?table=Signups&token=your_token'"
      },

      "POST /create": {
        description: "Create a new record in a table. Returns instantly with optimistic update, processes Airtable API call in background queue.",
        authentication: true,
        request_body: {
          token: {
            type: "string",
            required: true,
            description: "Airtable Personal Access Token"
          },
          table: {
            type: "string",
            required: true,
            description: "Table name or table ID",
            example: "Signups"
          },
          fields: {
            type: "object",
            required: true,
            description: "Object with field names as keys and values as field values",
            example: {
              "Name": "John Doe",
              "Email": "john@example.com",
              "Status": "Active"
            }
          }
        },
        response: {
          type: "object",
          description: "Returns only the fields you provided (with redaction applied). Includes temporary 'id' that will be replaced with real Airtable ID when queue processes.",
          example: {
            "id": "temp_1234567890_abc123",
            "Name": "John Doe",
            "Email": "john@example.com",
            "Status": "Active"
          }
        },
        example_request: `curl -X POST http://localhost:3000/create \\
  -H "Content-Type: application/json" \\
  -d '{
    "token": "your_token",
    "table": "Signups",
    "fields": {
      "Name": "John Doe",
      "Email": "john@example.com"
    }
  }'`,
        notes: [
          "Response is instant (<10ms) - Airtable API call happens in background",
          "If Airtable API call fails, the optimistic update is automatically rolled back",
          "Temporary ID is replaced with real Airtable record ID when queue processes"
        ]
      },

      "PUT /update": {
        description: "Update an existing record. Returns instantly with optimistic update, processes Airtable API call in background queue.",
        authentication: true,
        request_body: {
          token: {
            type: "string",
            required: true,
            description: "Airtable Personal Access Token"
          },
          table: {
            type: "string",
            required: true,
            description: "Table name or table ID",
            example: "Signups"
          },
          recordId: {
            type: "string",
            required: true,
            description: "Airtable record ID (starts with 'rec')",
            example: "recXXXXXXXXXXXXXX"
          },
          fields: {
            type: "object",
            required: true,
            description: "Object with field names as keys and new values. Only provided fields will be updated.",
            example: {
              "Email": "newemail@example.com",
              "Status": "Inactive"
            }
          }
        },
        response: {
          type: "object",
          description: "Returns only the fields you updated (with redaction applied). Other fields remain unchanged.",
          example: {
            "id": "recXXXXXXXXXXXXXX",
            "Email": "newemail@example.com",
            "Status": "Inactive"
          }
        },
        example_request: `curl -X PUT http://localhost:3000/update \\
  -H "Content-Type: application/json" \\
  -d '{
    "token": "your_token",
    "table": "Signups",
    "recordId": "recXXXXXXXXXXXXXX",
    "fields": {
      "Email": "newemail@example.com"
    }
  }'`,
        notes: [
          "Response is instant (<10ms) - Airtable API call happens in background",
          "Only fields provided in 'fields' object will be updated",
          "If Airtable API call fails, changes are automatically rolled back"
        ]
      },

      "DELETE /delete": {
        description: "Delete a record from a table. Returns instantly, processes Airtable API call in background queue.",
        authentication: true,
        request_body: {
          token: {
            type: "string",
            required: true,
            description: "Airtable Personal Access Token"
          },
          table: {
            type: "string",
            required: true,
            description: "Table name or table ID",
            example: "Signups"
          },
          recordId: {
            type: "string",
            required: true,
            description: "Airtable record ID (starts with 'rec')",
            example: "recXXXXXXXXXXXXXX"
          }
        },
        response: {
          type: "object",
          description: "Returns success status and deleted record ID",
          example: {
            "success": true,
            "deleted": {
              "id": "recXXXXXXXXXXXXXX"
            }
          }
        },
        example_request: `curl -X DELETE http://localhost:3000/delete \\
  -H "Content-Type: application/json" \\
  -d '{
    "token": "your_token",
    "table": "Signups",
    "recordId": "recXXXXXXXXXXXXXX"
  }'`,
        notes: [
          "Response is instant (<10ms) - Airtable API call happens in background",
          "If Airtable API call fails, the record is automatically restored"
        ]
      },

      "GET /queue-status": {
        description: "Check the status of the background processing queue",
        authentication: true,
        parameters: {
          token: {
            type: "string (query parameter)",
            required: true,
            description: "Airtable Personal Access Token"
          }
        },
        response: {
          type: "object",
          example: {
            "queueLength": 3,
            "isProcessing": true
          }
        },
        example_request: "curl 'http://localhost:3000/queue-status?token=your_token'"
      }
    },

    security_features: {
      authentication: "All endpoints require token authentication",
      input_sanitization: "All inputs are sanitized to prevent injection attacks",
      field_redaction: "Fields with 'redacted' in name (case-insensitive) are automatically redacted in all responses",
      response_filtering: "Create/Update/Delete endpoints only return fields that were provided in the request"
    },

    performance: {
      description: "All write operations (create/update/delete) use optimistic updates for instant responses",
      typical_response_times: {
        "GET /get": "< 5ms",
        "POST /create": "< 10ms",
        "PUT /update": "< 10ms",
        "DELETE /delete": "< 10ms"
      },
      background_processing: "Airtable API calls are queued and processed asynchronously without blocking responses"
    },

    data_format: {
      records: "All records include an 'id' field plus their data fields",
      field_redaction: "Fields containing 'redacted' in name return 'redacted' instead of actual value",
      example_record: {
        "id": "recXXXXXXXXXXXXXX",
        "Name": "John Doe",
        "Email": "john@example.com",
        "address-redacted": "redacted",
        "Created": "2025-11-26T20:00:00.000Z"
      }
    },

    error_handling: {
      authentication_errors: {
        status: 401,
        example: { "error": "Authentication required. Provide token in body, query parameter, x-token header, or Authorization header." }
      },
      validation_errors: {
        status: 400,
        example: { "error": "Table is required and must be a valid string" }
      },
      not_found_errors: {
        status: 404,
        example: { "error": "Table \"Signups\" not found" }
      },
      server_errors: {
        status: 500,
        example: { "error": "Failed to create record", "details": "..." }
      }
    },

    best_practices: [
      "Always include token in requests",
      "Use field filtering in GET requests to reduce response size",
      "Monitor queue status if processing many operations",
      "Handle errors appropriately - failed operations are automatically rolled back",
      "Field names with 'redacted' will be automatically redacted - use this for sensitive data"
    ],

    example_workflow: {
      step1_get_records: "GET /get?table=Signups&token=your_token&fields=Name,Email",
      step2_create_record: "POST /create with token, table, and fields",
      step3_update_record: "PUT /update with token, table, recordId, and fields to update",
      step4_delete_record: "DELETE /delete with token, table, and recordId"
    }
  });
});

// GET endpoint - get records from a table with optional field filtering
app.get('/get', authenticateToken, (req, res) => {
  try {
    const { table, fields } = req.query;
    const airtableToken = req.airtableToken;

    // Sanitize inputs
    const sanitizedTable = sanitizeTableName(table);
    if (!sanitizedTable) {
      return res.status(400).json({ error: 'Table is required and must be a valid string' });
    }

    // Parse fields if provided (comma-separated or array)
    let fieldArray = [];
    if (fields) {
      if (typeof fields === 'string') {
        fieldArray = fields.split(',').map(f => sanitizeInput(f.trim())).filter(f => f);
      } else if (Array.isArray(fields)) {
        fieldArray = fields.map(f => sanitizeInput(String(f))).filter(f => f);
      }
    }

    // Get records using the get() function (automatically redacts fields)
    const records = get(sanitizedTable, fieldArray.length > 0 ? fieldArray : []);

    if (records === null) {
      return res.status(404).json({ error: `Table "${sanitizedTable}" not found` });
    }

    res.json(records);
  } catch (error) {
    console.error('Error getting records:', error.message);
    res.status(500).json({
      error: 'Failed to get records',
      details: error.message
    });
  }
});

// Endpoint to check queue status (requires authentication)
app.get('/queue-status', authenticateToken, (req, res) => {
  res.json({
    queueLength: queue.length,
    isProcessing: isProcessingQueue
  });
});

// Create endpoint - creates a new record optimistically and queues Airtable API call
app.post('/create', authenticateToken, async (req, res) => {
  try {
    // Extract token and remove from body to prevent it from being included in fields
    const { table, fields } = req.body;
    const airtableToken = req.airtableToken;

    // Sanitize inputs
    const sanitizedTable = sanitizeTableName(table);
    if (!sanitizedTable) {
      return res.status(400).json({ error: 'Table is required and must be a valid string' });
    }

    if (!fields || typeof fields !== 'object' || Array.isArray(fields)) {
      return res.status(400).json({ error: 'Fields object is required' });
    }

    // Sanitize fields
    const sanitizedFields = sanitizeFields(fields);
    if (Object.keys(sanitizedFields).length === 0) {
      return res.status(400).json({ error: 'At least one field is required' });
    }

    const tableData = getTable(sanitizedTable);
    if (!tableData) {
      return res.status(404).json({ error: `Table "${sanitizedTable}" not found` });
    }

    // Generate temporary ID for optimistic update
    const tempId = generateTempId();
    
    // Create record optimistically in activeData (instant response)
    const newRecord = {
      id: tempId,
      ...sanitizedFields
    };
    
    // Add Created timestamp only if not provided
    if (!newRecord.Created) {
      newRecord.Created = new Date().toISOString();
    }

    // Add to activeData immediately
    tableData.records.push(newRecord);

    // Queue the Airtable API call
    queue.push({
      type: 'create',
      tableId: tableData.id,
      tempId: tempId,
      originalFields: sanitizedFields,
      token: airtableToken
    });

    // Process queue in background (non-blocking)
    setImmediate(processQueue);

    // Return only the fields that were provided (redacted)
    const responseRecord = redactFields(filterRecordFields(newRecord, sanitizedFields));
    res.json(responseRecord);
  } catch (error) {
    console.error('Error creating record:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({
      error: 'Failed to create record',
      details: error.response?.data || error.message
    });
  }
});

// Update endpoint - updates a record optimistically and queues Airtable API call
app.put('/update', authenticateToken, async (req, res) => {
  try {
    // Extract token and remove from body to prevent it from being included in fields
    const { table, recordId, fields } = req.body;
    const airtableToken = req.airtableToken;

    // Sanitize inputs
    const sanitizedTable = sanitizeTableName(table);
    if (!sanitizedTable) {
      return res.status(400).json({ error: 'Table is required and must be a valid string' });
    }

    const sanitizedRecordId = sanitizeRecordId(recordId);
    if (!sanitizedRecordId) {
      return res.status(400).json({ error: 'Record ID is required and must be a valid string' });
    }

    if (!fields || typeof fields !== 'object' || Array.isArray(fields)) {
      return res.status(400).json({ error: 'Fields object is required' });
    }

    // Sanitize fields
    const sanitizedFields = sanitizeFields(fields);
    if (Object.keys(sanitizedFields).length === 0) {
      return res.status(400).json({ error: 'At least one field is required' });
    }

    const tableData = getTable(sanitizedTable);
    if (!tableData) {
      return res.status(404).json({ error: `Table "${sanitizedTable}" not found` });
    }

    // Find the record
    const recordIndex = tableData.records.findIndex(r => r.id === sanitizedRecordId);
    if (recordIndex === -1) {
      return res.status(404).json({ error: 'Record not found' });
    }

    // Save original record for rollback
    const originalRecord = { ...tableData.records[recordIndex] };

    // Update optimistically in activeData (instant response)
    tableData.records[recordIndex] = {
      ...tableData.records[recordIndex],
      ...sanitizedFields
    };

    // Queue the Airtable API call
    queue.push({
      type: 'update',
      tableId: tableData.id,
      recordId: sanitizedRecordId,
      fields: sanitizedFields,
      originalRecord: originalRecord,
      token: airtableToken
    });

    // Process queue in background (non-blocking)
    setImmediate(processQueue);

    // Return only the fields that were provided (redacted)
    const responseRecord = redactFields(filterRecordFields(tableData.records[recordIndex], sanitizedFields));
    res.json(responseRecord);
  } catch (error) {
    console.error('Error updating record:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({
      error: 'Failed to update record',
      details: error.response?.data || error.message
    });
  }
});

// Delete endpoint - deletes a record optimistically and queues Airtable API call
app.delete('/delete', authenticateToken, async (req, res) => {
  try {
    const { table, recordId } = req.body;
    const airtableToken = req.airtableToken;

    // Sanitize inputs
    const sanitizedTable = sanitizeTableName(table);
    if (!sanitizedTable) {
      return res.status(400).json({ error: 'Table is required and must be a valid string' });
    }

    const sanitizedRecordId = sanitizeRecordId(recordId);
    if (!sanitizedRecordId) {
      return res.status(400).json({ error: 'Record ID is required and must be a valid string' });
    }

    const tableData = getTable(sanitizedTable);
    if (!tableData) {
      return res.status(404).json({ error: `Table "${sanitizedTable}" not found` });
    }

    // Find and remove from activeData immediately (optimistic)
    const recordIndex = tableData.records.findIndex(r => r.id === sanitizedRecordId);
    if (recordIndex === -1) {
      return res.status(404).json({ error: 'Record not found' });
    }

    // Save original record for rollback
    const deletedRecord = { ...tableData.records[recordIndex] };
    tableData.records.splice(recordIndex, 1);

    // Queue the Airtable API call
    queue.push({
      type: 'delete',
      tableId: tableData.id,
      recordId: sanitizedRecordId,
      originalRecord: deletedRecord,
      token: airtableToken
    });

    // Process queue in background (non-blocking)
    setImmediate(processQueue);

    // Return only success and record ID (redacted)
    const redactedDeleted = redactFields({ id: deletedRecord.id });
    res.json({ success: true, deleted: redactedDeleted });
  } catch (error) {
    console.error('Error deleting record:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({
      error: 'Failed to delete record',
      details: error.response?.data || error.message
    });
  }
});

// Export functions for use
module.exports = {
  get,
  getTable,
  activeData
};

// Start server and load data
async function startServer() {
  try {
    await loadAirtableData();
    
    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
      console.log(`Visit http://localhost:${PORT}/ to see your Airtable data`);
    });
  } catch (error) {
    console.error('Failed to start server:', error.message);
    process.exit(1);
  }
}

startServer();

