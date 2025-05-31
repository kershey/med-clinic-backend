from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Java Medical Backend API is running"}
