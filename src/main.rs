use axum::{
    extract::{Query, Request, State},
    http::HeaderName,
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Router,
};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use blake3::Hash;
use dashmap::DashSet;
use rand::{distributions::Alphanumeric, Rng};
use reqwest::{
    header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    Client,
};
use sqlx::{
    query,
    sqlite::{SqliteAutoVacuum, SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
    SqlitePool,
};
use std::str::FromStr;
use std::{
    borrow::Cow,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};
use tera::{Context, Tera};
use tokio::{net::TcpListener, runtime::Builder as RuntimeBuilder, time::Instant};
use tower_sombrero::{
    csp::CspNonce,
    headers::{ContentSecurityPolicy, CspSource},
    Sombrero,
};

const DEFAULT_TEMPLATES: [(&str, &str); 6] = [
    ("base.jinja", include_str!("../templates/base.jinja")),
    ("index.jinja", include_str!("../templates/index.jinja")),
    ("answer.jinja", include_str!("../templates/answer.jinja")),
    ("auth.jinja", include_str!("../templates/auth.jinja")),
    ("macros.jinja", include_str!("../templates/macros.jinja")),
    ("style.css", include_str!("../templates/style.css")),
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
        let mut tera = Tera::new(&format!("{path}/**/*.{{jinja,css}}")).expect("Tera parse failed");

        tera.autoescape_on(vec![".html", ".jinja"]);
        tera
    } else {
        let mut tera = Tera::default();
        tera.add_raw_templates(DEFAULT_TEMPLATES).unwrap();
        tera.autoescape_on(vec![".html", ".jinja"]);
        tera
    };

    let tokens = Arc::new(DashSet::new());

    let csp = ContentSecurityPolicy::strict_default()
        .remove_base_uri()
        .script_src([CspSource::UnsafeInline])
        .style_src([CspSource::Nonce]);
    let sombrero = Sombrero::default().content_security_policy(csp);

    let auth_layer = axum::middleware::from_fn_with_state(tokens.clone(), auth_layer);
    let router = Router::new()
        .route("/answer", get(answer_page).post(answer_form))
        .route("/delete", post(delete_question))
        .layer(auth_layer)
        .route("/style.css", get(style))
        .route("/", get(get_questions).post(ask_question))
        .route("/auth", get(auth_page).post(auth_set))
        .layer(sombrero);

    let addr = SocketAddr::from_str(&config.bind_address).expect("Failed to parse bind address");

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
        mastodon_config: config.mastodon.map(|cfg| MastodonState {
            api_auth: Arc::new(
                HeaderValue::from_str(&format!("Bearer {}", cfg.api_token))
                    .expect("Invalid token bytes"),
            ),
            api_url: format!("{}/api/v1/statuses", cfg.api_url).into(),
        }),
        ntfy_config: config.ntfy.map(|cfg| NtfyState {
            api_auth: Arc::new(
                HeaderValue::from_str(&format!("Bearer {}", cfg.api_token))
                    .expect("Invalid token bytes"),
            ),
            api_url: cfg.api_url.into(),
        }),
        password_hash: blake3::hash(config.password.as_bytes()),
        tokens,
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
    State(tokens): State<Arc<DashSet<String>>>,
    cookies: CookieJar,
    request: Request,
    next: Next,
) -> Response {
    let now = Instant::now();
    let security_wait =
        tokio::time::sleep_until(now.checked_add(Duration::from_millis(30)).unwrap_or(now));
    if cookies
        .get("questions-auth")
        .is_some_and(|provided| tokens.contains(provided.value()))
    {
        security_wait.await;
        next.run(request).await
    } else {
        security_wait.await;
        Redirect::to("/auth").into_response()
    }
}

#[derive(serde::Deserialize)]
struct AuthSetArgs {
    password: String,
}

async fn auth_set(
    State(state): State<AppState>,
    cookies: CookieJar,
    Form(args): Form<AuthSetArgs>,
) -> (CookieJar, Redirect) {
    if blake3::hash(args.password.as_bytes()) == state.password_hash {
        let new_token: String = rand::thread_rng()
            .sample_iter(Alphanumeric)
            .take(64)
            .map(|c| c as char)
            .collect();
        state.tokens.insert(new_token.clone());
        let cookie = Cookie::build(("questions-auth", new_token))
            .http_only(true)
            .secure(true)
            .build();
        (cookies.add(cookie), Redirect::to("/answer"))
    } else {
        (cookies, Redirect::to("/auth?bad=true"))
    }
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
    CspNonce(nonce): CspNonce,
    Query(args): Query<AuthPageArgs>,
) -> Result<Html<String>, Error> {
    let mut context = Context::new();
    context.insert("bad", &args.bad);
    context.insert("nonce", &nonce);
    Ok(Html(state.tera.render("auth.jinja", &context)?))
}

async fn get_questions(
    State(state): State<AppState>,
    CspNonce(nonce): CspNonce,
) -> Result<Html<String>, Error> {
    let answers: Vec<Answer> = query!(
        "SELECT questions.id, questions.question, questions.submitted_time, \
        questions.content_warning, answers.answer, answers.answer_time \
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
            content_warning: row.content_warning,
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
    context.insert("nonce", &nonce);
    Ok(Html(state.tera.render("index.jinja", &context)?))
}

#[derive(serde::Deserialize)]
struct FormAskQuestion {
    question: String,
    content_warning: String,
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
    if question_trim.contains('\n') {
        return Err(Error::NoNewlines);
    }

    let trimmed_content_warning = question.content_warning.trim();

    let content_warning = if trimmed_content_warning.is_empty() {
        None
    } else {
        Some(trimmed_content_warning.to_owned())
    };

    ntfy_question(&state, question_trim).await?;

    query!(
        "INSERT INTO questions (question, submitted_time, content_warning) VALUES (?1, ?2, ?3)",
        question_trim,
        now,
        content_warning
    )
    .execute(&state.db)
    .await?;
    Ok(Redirect::to("/"))
}

async fn ntfy_question(state: &AppState, question: &str) -> Result<(), Error> {
    let Some(config) = &state.ntfy_config else {
        return Ok(());
    };
    state
        .client
        .post(config.api_url.as_ref())
        .header(AUTHORIZATION, config.api_auth.as_ref())
        .body(question.to_owned())
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

#[derive(serde::Deserialize)]
struct FormAnswer {
    id: i64,
    answer: String,
    content_warning: String,
}

async fn answer_form(
    State(state): State<AppState>,
    Form(answer): Form<FormAnswer>,
) -> Result<Redirect, Error> {
    let now = now_secs();
    let answer_trim = answer.answer.trim();
    query!(
        "INSERT INTO answers (id, answer, answer_time) VALUES (?1, ?2, ?3)",
        answer.id,
        answer_trim,
        now
    )
    .execute(&state.db)
    .await?;

    let trimmed_content_warning = answer.content_warning.trim();

    let content_warning = if trimmed_content_warning.is_empty() {
        None
    } else {
        Some(trimmed_content_warning.to_owned())
    };

    query!(
        "UPDATE questions SET content_warning = ?2 WHERE id = ?1",
        answer.id,
        content_warning
    )
    .execute(&state.db)
    .await?;

    answer_mastodon(&state, answer.id).await?;

    Ok(Redirect::to("/answer"))
}

#[derive(serde::Serialize)]
struct MastodonPost {
    status: String,
    spoiler_text: Cow<'static, str>,
    language: &'static str,
    visibility: &'static str,
}

async fn answer_mastodon(state: &AppState, id: i64) -> Result<(), Error> {
    let Some(config) = &state.mastodon_config else {
        return Ok(());
    };

    let answer = query!(
        "SELECT questions.question, questions.content_warning, answers.answer FROM questions \
        LEFT JOIN answers WHERE answers.id = ?1 AND questions.id = ?1",
        id
    )
    .fetch_one(&state.db)
    .await?;

    let status = format!("{}\n{}", answer.question, answer.answer);

    let spoiler_text = if let Some(cw) = answer.content_warning {
        Cow::Owned(format!("anonymous question response (cw {cw})"))
    } else {
        Cow::Borrowed("anonymous question response")
    };

    let post = MastodonPost {
        status,
        spoiler_text,
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

async fn answer_page(
    State(state): State<AppState>,
    CspNonce(nonce): CspNonce,
) -> Result<Html<String>, Error> {
    let questions: Vec<Question> = query!(
        "SELECT questions.id, questions.question, \
        questions.submitted_time, questions.content_warning \
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
        content_warning: row.content_warning,
    })
    .collect();

    let mut context = Context::new();
    context.insert("questions", &questions);
    context.insert("nonce", &nonce);
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

async fn style(
    State(state): State<AppState>,
) -> Result<([(HeaderName, HeaderValue); 1], String), Error> {
    let css = state.tera.render("style.css", &Context::new())?;
    static CSS_CTYPE: HeaderValue = HeaderValue::from_static("text/css;charset=utf-8");
    Ok(([(CONTENT_TYPE, CSS_CTYPE.clone())], css))
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
    tokens: Arc<DashSet<String>>,
    password_hash: Hash,
    mastodon_config: Option<MastodonState>,
    ntfy_config: Option<NtfyState>,
}

#[derive(serde::Deserialize)]
struct Config {
    bind_address: String,
    database_path: String,
    template_path: Option<String>,
    password: String,
    mastodon: Option<RemoteServiceConfig>,
    ntfy: Option<RemoteServiceConfig>,
}

#[derive(serde::Deserialize)]
struct RemoteServiceConfig {
    api_token: String,
    api_url: String,
}

#[derive(Clone)]
struct MastodonState {
    api_auth: Arc<HeaderValue>,
    api_url: Arc<str>,
}

#[derive(Clone)]
struct NtfyState {
    api_auth: Arc<HeaderValue>,
    api_url: Arc<str>,
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
    #[error("No newlines allowed!")]
    NoNewlines,
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
    content_warning: Option<String>,
}
