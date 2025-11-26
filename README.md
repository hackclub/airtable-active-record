# Airtable Active Record API

A high-performance, secure Express.js API for interacting with Airtable data with optimistic updates and background queue processing.

## Features

- **Instant Responses**: All write operations return in <10ms using optimistic updates
- **Secure**: Token-based authentication, input sanitization, and automatic field redaction
- **Background Processing**: Airtable API calls are queued and processed asynchronously
- **In-Memory Cache**: All data is loaded on startup and kept in sync
- **Automatic Rollback**: Failed operations are automatically rolled back

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a `.env` file (optional - for initial data load):
   ```env
   base_id=your_airtable_base_id
   airtable_pat=your_airtable_personal_access_token
   PORT=3000
   ```

4. Start the server:
   ```bash
   npm start
   ```

The server will:
- Load all tables and records from your Airtable base on startup
- Start listening on port 3000 (or PORT from env)
- Be ready to handle API requests

## API Documentation

Visit `GET http://localhost:3000/` for comprehensive, LLM-friendly API documentation including:
- All available endpoints
- Request/response formats
- Example requests
- Error handling
- Security features
- Best practices

## Quick Start

### Authentication

All endpoints (except `GET /`) require a token. Provide it via:
- Request body: `{ "token": "your_token", ... }`
- Query parameter: `?token=your_token`
- Header: `x-token: your_token`
- Authorization header: `Authorization: Bearer your_token`

### Get Records

```bash
curl 'http://localhost:3000/get?table=Signups&token=your_token&fields=Name,Email'
```

### Create Record

```bash
curl -X POST http://localhost:3000/create \
  -H "Content-Type: application/json" \
  -d '{
    "token": "your_token",
    "table": "Signups",
    "fields": {
      "Name": "John Doe",
      "Email": "john@example.com"
    }
  }'
```

### Update Record

```bash
curl -X PUT http://localhost:3000/update \
  -H "Content-Type: application/json" \
  -d '{
    "token": "your_token",
    "table": "Signups",
    "recordId": "recXXXXXXXXXXXXXX",
    "fields": {
      "Email": "newemail@example.com"
    }
  }'
```

### Delete Record

```bash
curl -X DELETE http://localhost:3000/delete \
  -H "Content-Type: application/json" \
  -d '{
    "token": "your_token",
    "table": "Signups",
    "recordId": "recXXXXXXXXXXXXXX"
  }'
```

## Security Features

- **Token Authentication**: Every request requires a valid Airtable Personal Access Token
- **Input Sanitization**: All inputs are sanitized to prevent injection attacks
- **Field Redaction**: Fields with "redacted" in the name are automatically redacted
- **Response Filtering**: Only requested fields are returned in responses

## Performance

- **GET requests**: < 5ms (served from in-memory cache)
- **Write operations**: < 10ms (optimistic updates)
- **Background queue**: Processes Airtable API calls asynchronously

## Architecture

1. **Startup**: Loads all tables and records from Airtable into memory
2. **Read Operations**: Served instantly from in-memory cache
3. **Write Operations**: 
   - Update in-memory cache immediately (optimistic)
   - Queue Airtable API call for background processing
   - Rollback on failure

## Docker Deployment

### Build and Run Locally

```bash
# Build the image
docker build -t airtable-active-record .

# Run the container
docker run -p 3000:3000 \
  -e PORT=3000 \
  -e airtable_pat=your_airtable_personal_access_token \
  airtable-active-record
```

### Deploy to Coolify

1. **Push your code** to a Git repository (GitHub, GitLab, etc.)

2. **In Coolify**:
   - Create a new resource
   - Select "Docker Compose" or "Dockerfile"
   - Connect your Git repository
   - Coolify will automatically detect the Dockerfile

3. **Set Environment Variables** in Coolify:
   - `base_id=your_airtable_base_id` (required)
   - `PORT=3000` (Coolify will set this automatically, but you can override)
   - `airtable_pat=your_airtable_personal_access_token` (optional, for initial data load)

4. **Deploy** - Coolify will:
   - Build the Docker image
   - Start the container
   - Handle port mapping automatically
   - Provide health checks

The API will be available at your Coolify domain. The server will automatically load data from Airtable on startup (if `airtable_pat` is provided).

### Docker Features

- ✅ Uses Node.js 20 Alpine (small image size)
- ✅ Runs as non-root user for security
- ✅ Health check included
- ✅ Production dependencies only
- ✅ Optimized layer caching

## Configuration

The Airtable base ID can be configured via the `base_id` environment variable. If not set, it defaults to the hardcoded value in `server.js`.

**Environment Variables:**
- `base_id` - Your Airtable base ID (required)
- `airtable_pat` - Airtable Personal Access Token (optional, for initial data load)
- `PORT` - Server port (defaults to 3000)

## License

MIT

# airtable-active-record
