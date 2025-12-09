# OpenAI API Key Setup for LLM Integration

## Quick Setup

### 1. Get OpenAI API Key

1. Go to https://platform.openai.com/
2. Sign up or log in
3. Navigate to API Keys section
4. Create new secret key
5. Copy the key (starts with `sk-`)

### 2. Configure Backend

Create or edit `backend/.env`:

```bash
# LLM Configuration
OPENAI_API_KEY=sk-proj-your-actual-key-here
OPENAI_MODEL=gpt-4o
```

### 3. Install Dependencies

```bash
cd backend
pip install openai
# Or install all requirements:
pip install -r requirements.txt
```

### 4. Restart Backend

```bash
cd backend
uvicorn main:app --reload
```

### 5. Verify Integration

Check logs for:
```
[INFO] LLMAnalysisService initialized with OpenAI API
[INFO] LLM Model: gpt-4o
```

## Cost Information

**GPT-4o Pricing** (as of Dec 2024):
- Input: ~$2.50 per 1M tokens
- Output: ~$10.00 per 1M tokens

**Per Binary Analysis**:
- Input tokens: ~1,000-5,000 (strace log)
- Output tokens: ~300-800 (classification)
- **Estimated cost: $0.01-0.05 per binary**

## Without API Key

The system works fine without an API key:
- LLM analysis will be **disabled**
- Qiling, Ghidra, and GNN analyses still run
- Job JSON will show `llm_analysis_results.status: "disabled"`

## Alternative Models

### Use GPT-4-Turbo (cheaper)
```bash
OPENAI_MODEL=gpt-4-turbo
```

### Use GPT-3.5-Turbo (cheapest)
```bash
OPENAI_MODEL=gpt-3.5-turbo
```

## Security Notes

⚠️ **Important**:
- Keep your API key secret
- Add `.env` to `.gitignore`
- Don't commit API keys to git
- Rotate keys if exposed
- Set usage limits in OpenAI dashboard

## Troubleshooting

### "LLM analysis disabled (no API key)"
✅ Check `.env` file exists in `backend/` directory  
✅ Verify `OPENAI_API_KEY` is set correctly  
✅ Restart backend server  

### "OpenAI API call failed: 401 Unauthorized"
✅ API key is invalid or expired  
✅ Get new key from OpenAI dashboard  

### "OpenAI API call failed: 429 Rate limit"
✅ Too many requests  
✅ Check OpenAI usage dashboard  
✅ Upgrade plan or wait  

### "Import 'openai' could not be resolved"
✅ Install package: `pip install openai`  

## Testing

Test with a simple curl after setup:

```bash
# Upload a binary
curl -X POST http://localhost:8000/api/analyze \
  -F "file=@test_binary.elf"

# Get job status (wait a few seconds)
curl http://localhost:8000/api/jobs/<job_id>

# Check for llm_analysis_results in response
```

## Environment Variables Reference

```bash
# Required
OPENAI_API_KEY=sk-your-key-here

# Optional
OPENAI_MODEL=gpt-4o          # Default: gpt-4o
```

## Sample .env File

```bash
# Database
DATABASE_URL="postgresql://..."

# LLM Configuration
OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890
OPENAI_MODEL=gpt-4o

# Other backend configs...
```

## Monitoring Usage

Check OpenAI dashboard:
- https://platform.openai.com/usage
- View costs per day
- Set budget alerts
- Monitor rate limits

## Support

For issues:
1. Check backend logs: `backend/logs/`
2. Review `LLM_INTEGRATION.md`
3. Test with simple binary
4. Verify API key is active
