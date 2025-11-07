# Deployment Guide

## Railway Deployment

### Prerequisites
1. Create an account at [Railway.app](https://railway.app)
2. Install Railway CLI (optional): `npm install -g @railway/cli`

### Option 1: Deploy via Railway Dashboard
1. Connect your GitHub repository to Railway
2. Railway will automatically detect the Python app
3. Add environment variable: `FLASK_ENV=production`
4. Railway will automatically provision a PostgreSQL database
5. Deploy!

### Option 2: Deploy via CLI
```bash
# Login to Railway
railway login

# Initialize project
railway init

# Add PostgreSQL database
railway add postgresql

# Deploy
railway up

# Set environment variables
railway variables set FLASK_ENV=production
```

## Local Development

### Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

The app will be available at `http://localhost:5000`

### Environment Variables
Copy `.env.example` to `.env` and modify as needed:
```bash
cp .env.example .env
```

## Features Added in This Version

### Enhanced Functionality
- ✅ **Pagination**: Handle large numbers of universes
- ✅ **Delete Operations**: Remove universes and characters
- ✅ **Error Handling**: Proper error pages and validation
- ✅ **Input Validation**: Length limits and required fields
- ✅ **Database Transaction Safety**: Rollback on errors

### Production Ready
- ✅ **Environment Configuration**: Separate dev/prod configs
- ✅ **PostgreSQL Support**: Ready for Railway's managed database
- ✅ **Health Check Endpoint**: `/health` for monitoring
- ✅ **Proper Error Handlers**: 404/500 pages
- ✅ **Security**: Environment-based secret keys

### UI/UX Improvements
- ✅ **Better Navigation**: Consistent button styling
- ✅ **Confirmation Dialogs**: Before deleting items
- ✅ **Responsive Design**: Mobile-friendly pagination
- ✅ **Visual Feedback**: Flash messages for all operations

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | List all universes (paginated) |
| `/universe/<id>` | GET | View universe details and characters |
| `/add-universe` | GET/POST | Create new universe form |
| `/universe/<id>/add-character` | POST | Add character to universe |
| `/universe/<id>/delete` | POST | Delete universe |
| `/character/<id>/delete` | POST | Delete character |
| `/health` | GET | Health check endpoint |