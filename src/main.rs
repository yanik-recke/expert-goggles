mod osv;
mod parser;

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use log::{debug, error, info};
use osv::{DependencyReport, OsvService};
use parser::{Dependency, DependencyParser, gradle::GradleParser, maven::MavenParser};
use serde::Deserialize;

#[tokio::main]
async fn main() {
    env_logger::init();

    let app_state = Arc::new(AppState {
        osv_service: OsvService::new(),
    });

    let app: Router = Router::new()
        .route("/", get(hello_world))
        .route("/parse", post(parse_dependencies))
        .route("/check", post(check_vulnerabilities))
        .with_state(app_state);

    info!("Starting server on 0.0.0.0:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

struct AppState {
    osv_service: OsvService,
}

async fn hello_world(State(_): State<Arc<AppState>>) -> StatusCode {
    StatusCode::OK
}

#[derive(Deserialize)]
struct ParseRequest {
    content: String,
    file_type: String,
}

async fn parse_dependencies(
    _: State<Arc<AppState>>,
    Json(payload): Json<ParseRequest>,
) -> Result<Json<Vec<Dependency>>, (StatusCode, String)> {
    debug!(
        "Received parse request for file_type: {}",
        payload.file_type
    );

    let parser: Box<dyn DependencyParser> = match payload.file_type.as_str() {
        "pom.xml" | "maven" => Box::new(MavenParser),
        "gradle" => Box::new(GradleParser),
        other => {
            error!("Unsupported file type: {}", other);
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Unsupported file type: {}", other),
            ));
        }
    };

    match parser.parse(&payload.content) {
        Ok(deps) => {
            info!(
                "Parsed {} dependencies from {} file",
                deps.len(),
                payload.file_type
            );
            Ok(Json(deps))
        }
        Err(e) => {
            error!("Failed to parse {} file: {}", payload.file_type, e);
            Err((StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))
        }
    }
}

async fn check_vulnerabilities(
    state: State<Arc<AppState>>,
    Json(payload): Json<ParseRequest>,
) -> Result<Json<Vec<DependencyReport>>, (StatusCode, String)> {
    debug!(
        "Received check request for file_type: {}",
        payload.file_type
    );

    let deps = {
        let parser: Box<dyn DependencyParser> = match payload.file_type.as_str() {
            "pom.xml" | "maven" => Box::new(MavenParser),
            "gradle" => Box::new(GradleParser),
            other => {
                error!("Unsupported file type: {}", other);
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Unsupported file type: {}", other),
                ));
            }
        };

        parser
            .parse(&payload.content)
            .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?
    };

    info!("Parsed {} dependencies, checking against OSV", deps.len());

    state
        .osv_service
        .check_dependencies(&deps)
        .await
        .map(Json)
        .map_err(|e| {
            error!("OSV API error: {}", e);
            (StatusCode::BAD_GATEWAY, e.to_string())
        })
}
