use axum::{
    body::{Body, Bytes},
    extract::{MatchedPath, Request, State},
    http::uri::Uri,
    http::HeaderMap,
    response::{IntoResponse, Response},
    Router,
};
use hyper::StatusCode;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use std::{io::Write, time::Duration};
use tokio::fs::OpenOptions;
use tokio::process::Command;
use tower_http::{classify::ServerErrorsFailureClass, trace::TraceLayer};
use tracing::{info, info_span, Span};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

type Client = hyper_util::client::legacy::Client<HttpConnector, Body>;

#[tokio::main]
async fn main() {
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("./logs/fresh1.log")
        .await
        .expect("Failed to open log file");

    let mut std_log_file = log_file.try_into_std().unwrap();
    std_log_file
        .write("cool TODO: date time en zo\n".as_bytes())
        .unwrap();

    let mut _child = Command::new("deno")
        .args(["run", "-A", "./ah-yes/main.ts"])
        .stdout(std_log_file.try_clone().unwrap())
        .stderr(std_log_file)
        .spawn()
        .expect("Failed to start process");

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!(
                    "{}=debug,tower_http=debug,axum::rejection=trace",
                    env!("CARGO_CRATE_NAME")
                )
                .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    let client: Client =
        hyper_util::client::legacy::Client::<(), ()>::builder(TokioExecutor::new())
            .build(HttpConnector::new());

    let app = Router::new().fallback(handler).with_state(client).layer(
        TraceLayer::new_for_http()
            .make_span_with(|request: &Request<_>| {
                let matched_path = request
                    .extensions()
                    .get::<MatchedPath>()
                    .map(MatchedPath::as_str);

                info_span!(
                    "http_request",
                    method = ?request.method(),
                    matched_path,
                    some_other_field = tracing::field::Empty,
                )
            })
            .on_request(|_request: &Request<_>, _span: &Span| {})
            .on_response(|_response: &Response, _latency: Duration, _span: &Span| {})
            .on_body_chunk(|_chunk: &Bytes, _latency: Duration, _span: &Span| {})
            .on_eos(|_trailers: Option<&HeaderMap>, _stream_duration: Duration, _span: &Span| {})
            .on_failure(|_error: ServerErrorsFailureClass, _latency: Duration, _span: &Span| {}),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn handler(State(client): State<Client>, mut req: Request) -> Result<Response, StatusCode> {
    let path = req.uri().path();
    let path_query = req
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or(path);
    info!(path_query);
    let uri = format!("http://127.0.0.1:8000{}", path_query);

    *req.uri_mut() = Uri::try_from(uri).unwrap();

    Ok(client
        .request(req)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .into_response())
}
