"""Start SOCForge bound to the local machine only. Python 3.10+ required."""
import os
import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=int(os.getenv("SOCFORGE_PORT", "8080")), reload=False)
