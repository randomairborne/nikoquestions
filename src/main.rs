use std::{net::SocketAddr, sync::Arc, time::UNIX_EPOCH};

use axum::{
    extract::{Query, Request, State},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use reqwest::{header::HeaderValue, header::AUTHORIZATION, Client};
use sqlx::{
    query,
    sqlite::{SqliteAutoVacuum, SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
    SqlitePool,
};
use tera::{Context, Tera};
use tokio::{net::TcpListener, runtime::Builder as RuntimeBuilder};

const DEFAULT_TEMPLATES: [(&str, &str); 4] = [
    ("base.jinja", include_str!("../templates/base.jinja")),
    ("index.jinja", include_str!("../templates/index.jinja")),
    ("answer.jinja", include_str!("../templates/answer.jinja")),
    ("auth.jinja", include_str!("../templates/auth.jinja")),
];

const MAX_QUESTION_LEN: usize = 10_000;

fn main() {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("config.toml"));
    let config = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|err| panic!("Could not read {config_path}: {err}"));
    let config: Config = toml::from_str(&config).expect("Invalid config file");

    let templates = if let Some(path) = config.template_path {
        Tera::new(&format!("{path}/**/*.jinja")).expect("Tera parse failed")
    } else {
        let mut tera = Tera::default();
        tera.add_raw_templates(DEFAULT_TEMPLATES).unwrap();
        tera
    };

    let auth_layer = axum::middleware::from_fn_with_state(config.password.clone(), auth_layer);
    let router = Router::new()
        .route("/answer", get(answer_page).post(answer_form))
        .route("/delete", post(delete_question))
        .layer(auth_layer)
        .route("/", get(get_questions).post(ask_question))
        .route("/auth", get(auth_page).post(auth_set));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));

    let rt = RuntimeBuilder::new_current_thread()
        .enable_all()
        .thread_name("niko-questions-main")
        .build()
        .unwrap();

    let database_conn = rt.block_on(async {
        let db_opts = SqliteConnectOptions::new()
            .create_if_missing(true)
            .optimize_on_close(true, None)
            .auto_vacuum(SqliteAutoVacuum::Incremental)
            .journal_mode(SqliteJournalMode::Wal)
            .filename(&config.database_path);
        let db = SqlitePoolOptions::new()
            .min_connections(5)
            .connect_with(db_opts)
            .await
            .unwrap_or_else(|e| panic!("Failed to open DB at {}: {e}", config.database_path));
        sqlx::migrate!()
            .run(&db)
            .await
            .expect("failed to run migrations");
        db
    });

    let state = AppState {
        db: database_conn,
        tera: Arc::new(templates),
        client: Client::new(),
        mastodon_config: config.mastodon_config.map(|cfg| MastodonState {
            api_auth: Arc::new(
                HeaderValue::from_str(&format!("Bearer {}", cfg.mastodon_api_token))
                    .expect("Invalid token bytes"),
            ),
            api_url: format!("{}/api/v1/statuses", cfg.mastodon_api_url).into(),
        }),
    };

    let router = router.with_state(state);

    let server = rt.spawn(serve(addr, router));
    println!("Listening on address: {}", addr);
    rt.block_on(server)
        .unwrap()
        .expect("Could not start server");
}

async fn serve(address: SocketAddr, app: Router) -> Result<(), std::io::Error> {
    let tcp = TcpListener::bind(address).await?;
    axum::serve(tcp, app).await
}

async fn auth_layer(
    State(password): State<Arc<str>>,
    cookies: CookieJar,
    request: Request,
    next: Next,
) -> Response {
    if cookies
        .get("questions-auth")
        .is_some_and(|provided| *provided.value() == *password)
    {
        next.run(request).await
    } else {
        Redirect::to("/auth?bad=true").into_response()
    }
}

#[derive(serde::Deserialize)]
struct AuthSetArgs {
    password: String,
}

async fn auth_set(cookies: CookieJar, Form(args): Form<AuthSetArgs>) -> (CookieJar, Redirect) {
    let cookie = Cookie::build(("questions-auth", args.password))
        .http_only(true)
        .secure(true)
        .build();
    (cookies.add(cookie), Redirect::to("/answer"))
}

#[derive(serde::Deserialize)]
struct AuthPageArgs {
    #[serde(default = "default_false")]
    bad: bool,
}

fn default_false() -> bool {
    false
}

async fn auth_page(
    State(state): State<AppState>,
    Query(args): Query<AuthPageArgs>,
) -> Result<Html<String>, Error> {
    let mut context = Context::new();
    context.insert("bad", &args.bad);
    Ok(Html(state.tera.render("auth.jinja", &context)?))
}

async fn get_questions(State(state): State<AppState>) -> Result<Html<String>, Error> {
    let answers: Vec<Answer> = query!(
        "SELECT questions.id, questions.question, questions.submitted_time, \
        answers.answer, answers.answer_time \
        FROM questions \
        LEFT JOIN answers WHERE answers.id = questions.id \
        ORDER BY answers.answer_time"
    )
    .fetch_all(&state.db)
    .await?
    .into_iter()
    .map(|row| {
        let question = Question {
            id: row.id,
            question: row.question,
            submitted_time: row.submitted_time,
        };
        Answer {
            answer: row.answer,
            answer_time: row.answer_time,
            question,
        }
    })
    .collect();
    let mut context = Context::new();
    context.insert("answers", &answers);
    Ok(Html(state.tera.render("index.jinja", &context)?))
}

#[derive(serde::Deserialize)]
struct FormAskQuestion {
    question: String,
}

async fn ask_question(
    State(state): State<AppState>,
    Form(question): Form<FormAskQuestion>,
) -> Result<Redirect, Error> {
    let now = now_secs();
    let question_trim = question.question.trim();

    if question_trim.len() > MAX_QUESTION_LEN {
        return Err(Error::TooLong);
    }
    if question_trim.is_empty() {
        return Err(Error::TooShort);
    }

    query!(
        "INSERT INTO questions (question, submitted_time) VALUES (?1, ?2)",
        question_trim,
        now
    )
    .execute(&state.db)
    .await?;
    Ok(Redirect::to("/"))
}

#[derive(serde::Deserialize)]
struct FormAnswer {
    id: i64,
    answer: String,
}

async fn answer_form(
    State(state): State<AppState>,
    Form(args): Form<FormAnswer>,
) -> Result<Redirect, Error> {
    let now = now_secs();
    let answer_trim = args.answer.trim();
    query!(
        "INSERT INTO answers (id, answer, answer_time) VALUES (?1, ?2, ?3)",
        args.id,
        answer_trim,
        now
    )
    .execute(&state.db)
    .await?;

    answer_mastodon(&state, args.id).await?;

    Ok(Redirect::to("/answer"))
}

#[derive(serde::Serialize)]
struct MastodonPost {
    status: String,
    spoiler_text: &'static str,
    language: &'static str,
    visibility: &'static str,
}

async fn answer_mastodon(state: &AppState, id: i64) -> Result<(), Error> {
    let Some(config) = &state.mastodon_config else {
        return Ok(());
    };

    let answer = query!(
        "SELECT questions.question, answers.answer FROM questions \
        LEFT JOIN answers WHERE answers.id = ?1 AND questions.id = ?1",
        id
    )
    .fetch_one(&state.db)
    .await?;

    let status = format!("{}\n{}", answer.question, answer.answer);

    let post = MastodonPost {
        status,
        spoiler_text: "anonymous question response",
        language: "en",
        visibility: "public",
    };

    state
        .client
        .post(config.api_url.as_ref())
        .header(AUTHORIZATION, config.api_auth.as_ref())
        .json(&post)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

async fn answer_page(State(state): State<AppState>) -> Result<Html<String>, Error> {
    let questions: Vec<Question> = query!(
        "SELECT questions.id, questions.question, questions.submitted_time \
        FROM questions WHERE NOT EXISTS
        (SELECT id FROM answers WHERE answers.id = questions.id)
        ORDER BY questions.submitted_time"
    )
    .fetch_all(&state.db)
    .await?
    .into_iter()
    .map(|row| Question {
        id: row.id,
        question: row.question,
        submitted_time: row.submitted_time,
    })
    .collect();

    let mut context = Context::new();
    context.insert("questions", &questions);
    Ok(Html(state.tera.render("answer.jinja", &context)?))
}

async fn delete_question(
    State(state): State<AppState>,
    Form(answer): Form<FormAnswer>,
) -> Result<Redirect, Error> {
    query!("DELETE FROM questions WHERE id = ?", answer.id)
        .execute(&state.db)
        .await?;
    Ok(Redirect::to("/answer"))
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |v| v.as_secs().try_into().unwrap_or(-1))
}

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    tera: Arc<Tera>,
    client: Client,
    mastodon_config: Option<MastodonState>,
}

#[derive(serde::Deserialize)]
struct Config {
    database_path: String,
    template_path: Option<String>,
    password: Arc<str>,
    #[serde(flatten)]
    mastodon_config: Option<MastodonConfig>,
}

#[derive(Clone)]
struct MastodonState {
    api_auth: Arc<HeaderValue>,
    api_url: Arc<str>,
}

#[derive(serde::Deserialize)]
struct MastodonConfig {
    mastodon_api_token: String,
    mastodon_api_url: String,
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("Templating error")]
    Tera(#[from] tera::Error),
    #[error("Database error")]
    Sqlx(#[from] sqlx::Error),
    #[error("HTTP error")]
    Http(#[from] reqwest::Error),
    #[error("Too long!")]
    TooLong,
    #[error("Too short!")]
    TooShort,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        eprintln!("ERROR: {self:?}");
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            self.to_string(),
        )
            .into_response()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Answer {
    answer_time: i64,
    answer: String,
    question: Question,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Question {
    id: i64,
    question: String,
    submitted_time: i64,
}
