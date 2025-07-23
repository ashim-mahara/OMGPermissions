from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Optional
import json
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer
import os


# Pydantic models
class PermissionRecord(BaseModel):
    permission: str
    application_guid: str
    delegated_guid: str
    display_application: str
    display_delegated: str
    description_application: str
    description_delegated: str
    admin_consent_application: bool
    admin_consent_delegated: bool


class SearchResult(BaseModel):
    record: PermissionRecord
    score: float


class QueryRequest(BaseModel):
    question: str
    top_k: Optional[int] = 3


class AnswerResponse(BaseModel):
    question: str
    answer: str
    context: List[PermissionRecord]


class HealthCheck(BaseModel):
    status: str
    record_count: int


# RAG Agent implementation
class PermissionsRAGAgent:
    def __init__(self, jsonl_file_path: str):
        self.jsonl_file_path = jsonl_file_path
        self.permissions_data = self._load_data()
        self.embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
        self.index = self._build_vector_index()

    def _load_data(self) -> List[PermissionRecord]:
        if not os.path.exists(self.jsonl_file_path):
            raise FileNotFoundError(
                f"Permissions file not found: {self.jsonl_file_path}"
            )

        data = []
        with open(self.jsonl_file_path, "r") as f:
            for line in f:
                try:
                    data.append(PermissionRecord(**json.loads(line)))
                except Exception as e:
                    print(f"Error parsing line: {line.strip()}. Error: {e}")
        return data

    def _build_vector_index(self) -> faiss.Index:
        texts = [self._record_to_text(record) for record in self.permissions_data]
        embeddings = self.embedding_model.encode(texts, normalize_embeddings=True)
        dimension = embeddings.shape[1]
        index = faiss.IndexFlatIP(dimension)
        index.add(embeddings)
        return index

    def _record_to_text(self, record: PermissionRecord) -> str:
        return (
            f"Permission: {record.permission} "
            f"Display Application: {record.display_application} "
            f"Display Delegated: {record.display_delegated} "
            f"Description Application: {record.description_application} "
            f"Description Delegated: {record.description_delegated} "
        )

    def search_permissions(self, query: str, top_k: int = 3) -> List[SearchResult]:
        query_embedding = self.embedding_model.encode(query, normalize_embeddings=True)
        query_embedding = np.expand_dims(query_embedding, axis=0)
        distances, indices = self.index.search(query_embedding, top_k)

        results = []
        for idx, distance in zip(indices[0], distances[0]):
            if idx >= 0:
                results.append(
                    SearchResult(
                        record=self.permissions_data[idx], score=float(distance)
                    )
                )
        return results

    def answer_question(self, question: str, top_k: int = 3) -> AnswerResponse:
        relevant_permissions = self.search_permissions(question, top_k)

        if not relevant_permissions:
            return AnswerResponse(
                question=question, answer="No relevant permissions found", context=[]
            )

        top_record = relevant_permissions[0].record

        if "display" in question.lower():
            answer = (
                f"Display names for {top_record.permission}: "
                f"Application: '{top_record.display_application}', "
                f"Delegated: '{top_record.display_delegated}'"
            )
        elif "admin consent" in question.lower():
            answer = (
                f"Admin consent requirements for {top_record.permission}: "
                f"Application: {'Required' if top_record.admin_consent_application else 'Not required'}, "
                f"Delegated: {'Required' if top_record.admin_consent_delegated else 'Not required'}"
            )
        elif "what" in question.lower() or "how" in question.lower():
            answer = (
                f"Permission {top_record.permission}:\n"
                f"- Application: {top_record.description_application}\n"
                f"- Delegated: {top_record.description_delegated}"
            )
        else:
            answer = (
                f"Found permission {top_record.permission}: "
                f"{top_record.description_application} "
                f"{top_record.description_delegated}"
            )

        return AnswerResponse(
            question=question,
            answer=answer,
            context=[result.record for result in relevant_permissions],
        )


# Initialize agent at startup
@asynccontextmanager
async def startup_event(app: FastAPI):
    # Get file path from environment variable or use default
    jsonl_path = os.getenv("PERMISSIONS_JSONL_PATH", "permissions.jsonl")
    app.state.agent = PermissionsRAGAgent(jsonl_path)
    yield


app = FastAPI(
    title="Permissions RAG API",
    description="API for querying Microsoft Graph permissions data",
    version="1.0.0",
    lifespan=startup_event,
)


# API Endpoints
@app.post("/ask", response_model=AnswerResponse, summary="Ask about permissions")
async def ask_question(request: QueryRequest):
    try:
        return app.state.agent.answer_question(request.question, request.top_k)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
    "/search", response_model=List[SearchResult], summary="Semantic permission search"
)
async def search_permissions(query: str, top_k: int = 3):
    try:
        return app.state.agent.search_permissions(query, top_k)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health", response_model=HealthCheck, summary="Service health check")
async def health_check():
    return {"status": "OK", "record_count": len(app.state.agent.permissions_data)}


@app.get(
    "/records/{permission_name}",
    response_model=PermissionRecord,
    summary="Get permission by name",
)
async def get_permission_by_name(permission_name: str):
    for record in app.state.agent.permissions_data:
        if record.permission.lower() == permission_name.lower():
            return record
    raise HTTPException(status_code=404, detail="Permission not found")


@app.get(
    "/records/guid/{guid}",
    response_model=List[PermissionRecord],
    summary="Get permissions by GUID (application or delegated)",
)
async def get_permissions_by_guid(guid: str):
    matches = [
        record
        for record in app.state.agent.permissions_data
        if record.application_guid.lower() == guid.lower()
        or record.delegated_guid.lower() == guid.lower()
    ]
    if not matches:
        raise HTTPException(status_code=404, detail="No permissions found for GUID")
    return matches


# Run with: uvicorn api:app --reload
