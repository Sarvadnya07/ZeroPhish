# ZeroPhish Deployment Checklist

Use this checklist to ensure proper setup and deployment of ZeroPhish.

---

## 📋 Pre-Deployment Checklist

### System Requirements
- [ ] Python 3.8 or higher installed
- [ ] Google Chrome browser installed
- [ ] Internet connection available
- [ ] Port 8000 available (not in use by other applications)

### Optional Requirements
- [ ] Redis installed (for production caching)
- [ ] Gemini API key (for optional Tier 3 AI)

---

## 🔧 Installation Checklist

### Backend Setup
- [ ] Navigate to Backend directory
- [ ] Create virtual environment: `python -m venv venv`
- [ ] Activate virtual environment
  - Windows: `venv\Scripts\activate`
  - macOS/Linux: `source venv/bin/activate`
- [ ] Install dependencies: `pip install -r requirements.txt`
- [ ] Verify installation: `python test_install.py`

### Configuration
- [ ] Review `Backend/.env` file
- [ ] Set `GEMINI_API_KEY` if using Tier 3 AI (optional)
- [ ] Review `Backend/tier_2/.env` file
- [ ] Set `REDIS_URL` if using Redis (optional)

### Extension Installation
- [ ] Open Chrome
- [ ] Navigate to `chrome://extensions/`
- [ ] Enable "Developer mode"
- [ ] Click "Load unpacked"
- [ ] Select `Backend/extension` folder
- [ ] Verify extension appears in extensions list

---

## ✅ Testing Checklist

### Backend Testing
- [ ] Start backend: `cd tier_2 && python main.py`
- [ ] Backend starts without errors
- [ ] Visit http://localhost:8000/health
- [ ] Health check returns "healthy" status
- [ ] Visit http://localhost:8000/docs
- [ ] API documentation loads correctly

### Extension Testing
- [ ] Open Gmail (https://mail.google.com)
- [ ] Open any email
- [ ] Click ZeroPhish extension icon
- [ ] Side panel opens
- [ ] Status shows "Ready to protect..."
- [ ] Click "INITIALIZE SCAN"
- [ ] Tier 1 analysis completes
- [ ] Backend communication succeeds (or shows offline message)
- [ ] Results display correctly

### API Testing
- [ ] Test scan endpoint with curl/PowerShell
- [ ] Response includes all required fields
- [ ] Threat score calculated correctly
- [ ] Evidence list populated
- [ ] Cache working (second identical request faster)

---

## 🔒 Security Checklist

### Environment Variables
- [ ] `.env` file exists and configured
- [ ] `.env` file NOT committed to git
- [ ] `.gitignore` includes `.env`
- [ ] No hardcoded API keys in code
- [ ] No sensitive data in logs

### Extension Permissions
- [ ] Review manifest.json permissions
- [ ] Only necessary permissions granted
- [ ] Host permissions limited to Gmail and localhost

### Network Security
- [ ] Backend only accessible on localhost (default)
- [ ] CORS configured appropriately
- [ ] No sensitive data sent to external services (except optional Gemini)

---

## 🚀 Production Checklist

### Performance Optimization
- [ ] Redis installed and running (recommended)
- [ ] Cache TTL configured appropriately
- [ ] WHOIS timeout configured
- [ ] Backend logging level set correctly

### Monitoring
- [ ] Backend health endpoint accessible
- [ ] Cache statistics endpoint working
- [ ] Error logging configured
- [ ] Performance metrics tracked

### Backup & Recovery
- [ ] Configuration files backed up
- [ ] Environment variables documented
- [ ] Recovery procedure documented
- [ ] Rollback plan prepared

---

## 📊 Verification Tests

### Test Case 1: Safe Email
```json
{
  "sender": "notifications@github.com",
  "body": "Your pull request was merged",
  "links": ["https://github.com/user/repo"]
}
```
- [ ] Expected: Low threat score (< 30)
- [ ] Expected: Verdict "SAFE"

### Test Case 2: Suspicious Email
```json
{
  "sender": "security@newdomain.com",
  "body": "Please verify your account immediately",
  "links": ["https://bit.ly/verify"]
}
```
- [ ] Expected: Medium threat score (30-69)
- [ ] Expected: Verdict "SUSPICIOUS"

### Test Case 3: Critical Threat
```json
{
  "sender": "urgent@suspicious-domain.xyz",
  "body": "URGENT: Your account will be suspended unless you verify immediately! Click here to avoid penalties.",
  "links": ["https://bit.ly/urgent-verify"]
}
```
- [ ] Expected: High threat score (70-100)
- [ ] Expected: Verdict "CRITICAL"
- [ ] Expected: Multiple flagged phrases

---

## 🐛 Troubleshooting Checklist

### If Backend Won't Start
- [ ] Check Python version: `python --version`
- [ ] Check port 8000 availability
- [ ] Verify all dependencies installed
- [ ] Check for syntax errors in code
- [ ] Review error messages in terminal

### If Extension Won't Load
- [ ] Verify manifest.json is valid JSON
- [ ] Check Chrome version compatibility
- [ ] Review extension console for errors
- [ ] Reload extension
- [ ] Reinstall extension

### If Scans Fail
- [ ] Verify backend is running
- [ ] Check backend URL in sidepanel.js
- [ ] Verify Gmail page is loaded
- [ ] Check browser console for errors
- [ ] Test backend API directly

### If Redis Issues
- [ ] Check Redis is running: `redis-cli ping`
- [ ] Verify REDIS_URL in .env
- [ ] Check Redis connection in backend logs
- [ ] System works without Redis (fallback mode)

---

## 📝 Documentation Checklist

### User Documentation
- [ ] README.md reviewed and accurate
- [ ] QUICK_REFERENCE.md available
- [ ] Installation instructions clear
- [ ] Troubleshooting guide complete

### Developer Documentation
- [ ] Code comments adequate
- [ ] API endpoints documented
- [ ] Configuration options explained
- [ ] Architecture documented

### Deployment Documentation
- [ ] FIXES_SUMMARY.md reviewed
- [ ] Deployment checklist (this file) complete
- [ ] Environment setup documented
- [ ] Recovery procedures documented

---

## 🎯 Go-Live Checklist

### Final Verification
- [ ] All tests passing
- [ ] No critical errors in logs
- [ ] Performance acceptable
- [ ] Security review complete
- [ ] Documentation complete

### Communication
- [ ] Users informed of new system
- [ ] Support contacts provided
- [ ] Known issues documented
- [ ] Feedback mechanism in place

### Post-Deployment
- [ ] Monitor backend logs
- [ ] Track error rates
- [ ] Collect user feedback
- [ ] Plan for updates and maintenance

---

## 📈 Success Metrics

### Performance Metrics
- [ ] Tier 1 analysis < 10ms
- [ ] Tier 2 analysis < 500ms
- [ ] Cached requests < 5ms
- [ ] Total scan time < 1 second

### Quality Metrics
- [ ] False positive rate acceptable
- [ ] False negative rate acceptable
- [ ] User satisfaction high
- [ ] System uptime > 99%

---

## 🔄 Maintenance Checklist

### Weekly
- [ ] Review backend logs
- [ ] Check cache hit rate
- [ ] Monitor error rates
- [ ] Update threat patterns if needed

### Monthly
- [ ] Update dependencies
- [ ] Review security advisories
- [ ] Backup configuration
- [ ] Performance review

### Quarterly
- [ ] Security audit
- [ ] Code review
- [ ] Documentation update
- [ ] User feedback review

---

## ✅ Sign-Off

- [ ] All checklist items completed
- [ ] System tested and verified
- [ ] Documentation reviewed
- [ ] Ready for deployment

**Deployed By:** ___________________

**Date:** ___________________

**Version:** 1.0

**Notes:**
```
[Add any deployment-specific notes here]
```

---

**Deployment Checklist Version: 1.0**
**Last Updated: 2026-02-11**
