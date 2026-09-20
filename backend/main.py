from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(
    title="PhishGuard API",
    description="Machine Learning based phishing detection API",
    version="1.0.0"
)


# Allow requests from our frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "message": "PhishGuard API is running!"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }