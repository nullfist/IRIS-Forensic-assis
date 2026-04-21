# IRIS Windows Setup Guide

## Quick Start (Easiest Method)

### Prerequisites
1. **Install Docker Desktop for Windows**
   - Download from: https://www.docker.com/products/docker-desktop/
   - During installation, enable WSL 2 backend (recommended)
   - Restart your computer after installation

2. **Verify Docker is Running**
   - Open Docker Desktop
   - Wait until you see the green status indicator (Docker is running)

### One-Click Start

1. **Double-click `start-iris.bat`** in the IRIS folder
2. Wait 2-3 minutes for all services to start
3. Your browser will automatically open to http://localhost:3000

That's it! The platform is now running with sample attack data loaded.

---

## Accessing IRIS

Once started, you can access:

| Service | URL | Credentials |
|---------|-----|-------------|
| **Web Interface** | http://localhost:3000 | None required |
| **API Documentation** | http://localhost:8000/docs | None required |
| **Neo4j Browser** | http://localhost:7474 | neo4j / irispassword |
| **Prometheus** | http://localhost:9090 | None required |
| **Grafana** | http://localhost:3001 | admin / admin |

---

## Stopping IRIS

To stop all services:
1. **Double-click `stop-iris.bat`** in the IRIS folder
2. Or close the command window (services will continue running in background)

To completely remove all data:
```cmd
docker-compose down -v
```

---

## Troubleshooting

### Docker Desktop Issues

**Problem**: Docker won't start or shows an error
**Solution**: 
- Make sure WSL 2 is enabled
- Run in PowerShell as Administrator: `wsl --install`
- Restart your computer

**Problem**: "Docker is not running" error in batch file
**Solution**: Open Docker Desktop and wait for the green status indicator

### Port Already in Use

**Problem**: "Port 3000 already in use" or similar
**Solution**: 
- Close any other applications using port 3000 (like Node.js servers)
- Or edit `docker-compose.yml` to use different ports

### Services Won't Start

**Problem**: Services fail to start
**Solution**:
1. Open a new Command Prompt
2. Run: `docker-compose down`
3. Run: `docker-compose up`
4. Watch the logs for specific errors

### Out of Memory

**Problem**: Containers crash or won't start
**Solution**:
- IRIS needs at least 8GB RAM (16GB recommended)
- Close other applications
- Increase Docker Desktop memory limit:
  - Docker Desktop → Settings → Resources → Memory → Set to 8GB or more

### Neo4j Issues

**Problem**: Neo4j won't start
**Solution**:
- Neo4j needs more memory - increase Docker memory to at least 4GB for Neo4j
- Check Neo4j logs: `docker-compose logs neo4j`

---

## Manual Setup (Alternative)

If the batch file doesn't work, you can start manually:

1. Open Command Prompt or PowerShell
2. Navigate to the IRIS folder:
   ```cmd
   cd "C:\Users\YourUsername\OneDrive\Desktop\IRIS-Forensic assis"
   ```
3. Start services:
   ```cmd
   docker-compose up -d
   ```
4. Wait 2-3 minutes, then open browser to http://localhost:3000

---

## Loading Sample Data Manually

If sample data wasn't loaded automatically:

1. Open Command Prompt
2. Navigate to IRIS folder
3. Run:
   ```cmd
   curl -X POST http://localhost:8000/api/v1/ingest ^
     -H "Content-Type: application/json" ^
     -d "{\"investigation_id\":\"demo-001\",\"enrich_graph\":true,\"artifacts\":[{\"source\":\"sysmon\",\"artifact_name\":\"demo.jsonl\",\"records\":[]}]"
   ```

Or use the API documentation at http://localhost:8000/docs to submit data through the web interface.

---

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 8GB | 16GB |
| Disk Space | 20GB | 50GB |
| CPU | 4 cores | 8 cores |
| OS | Windows 10/11 | Windows 11 |

---

## Need Help?

1. Check logs: `docker-compose logs -f`
2. View status: `docker-compose ps`
3. Restart services: `docker-compose restart`

For more detailed documentation, see [README.md](./README.md) and [DEMO.md](./DEMO.md).