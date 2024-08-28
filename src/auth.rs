use axum::{
    async_trait,
    extract::{FromRequestParts, Json, Request},
    http,
    http::{request::Parts, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    RequestPartsExt,
};

use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use dotenvy_macro::dotenv;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub size: usize,
    pub iat: usize,
    pub email: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError {
                message: "Invalid Token".to_string(),
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
            })?;
        let token_data = decode::<Claims>(bearer.token(), &KEYS.decoding, &Validation::default())
            .map_err(|_| AuthError {
            message: "Invalid Token".to_string(),
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
        })?;
        Ok(token_data.claims)
    }
}

#[derive(Deserialize)]
pub struct AuthPayload {
    pub email: String,
    pub password: String,
}
#[derive(Clone)]
pub struct CurrentUser {
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password_hash: String,
}

struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

pub struct AuthError {
    message: String,
    status_code: StatusCode,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        (self.status_code, Json(self.message)).into_response()
    }
}

impl Keys {
    fn init() -> Self {
        let secret = dotenv!("JWT_SECRET");
        Self {
            encoding: EncodingKey::from_secret(secret.as_ref()),
            decoding: DecodingKey::from_secret(secret.as_ref()),
        }
    }
}
static KEYS: Lazy<Keys> = Lazy::new(|| Keys::init());

pub async fn sign_in(Json(user_data): Json<AuthPayload>) -> Result<Json<String>, StatusCode> {
    let user = match retrieve_user_by_email() {
        Some(user) => user,
        None => return Err(StatusCode::UNAUTHORIZED),
    };
    if !verify_password(&user_data.password, &user.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = encode_jwt(user.email).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(token))
}

// Function to simulate retrieving user data from a database based on email
fn retrieve_user_by_email() -> Option<CurrentUser> {
    // For demonstration purposes, a hardcoded user is returned based on the provided email
    let current_user: CurrentUser = CurrentUser {
        email: "myemail@gmail.com".to_string(),
        first_name: "Eze".to_string(),
        last_name: "Sunday".to_string(),
        password_hash: "$2b$12$Gwf0uvxH3L7JLfo0CC/NCOoijK2vQ/wbgP.LeNup8vj6gg31IiFkm".to_string(),
    };
    Some(current_user) // Return the hardcoded user
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    let hash = hash(password, DEFAULT_COST)?;
    Ok(hash)
}

pub fn encode_jwt(email: String) -> Result<String, StatusCode> {
    let now = Utc::now();
    let expire: chrono::TimeDelta = Duration::hours(24);
    let exp: usize = (now + expire).timestamp() as usize;
    let iat: usize = now.timestamp() as usize;
    let claim = Claims {
        size: exp,
        iat,
        email,
    };

    encode(&Header::default(), &claim, &KEYS.encoding)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub fn decode_jwt(jwt_token: String) -> Result<TokenData<Claims>, StatusCode> {
    let result: Result<TokenData<Claims>, StatusCode> =
        decode::<Claims>(&jwt_token, &KEYS.decoding, &Validation::default()).map_err(|error| {
            match error.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => StatusCode::UNAUTHORIZED,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            }
        });
    result
}

pub async fn authorize(mut req: Request, next: Next) -> Result<impl IntoResponse, AuthError> {
    let auth_header = match req.headers_mut().get(http::header::AUTHORIZATION) {
        Some(header) => header.to_str().map_err(|_| AuthError {
            message: "Empty header is not allowed".to_string(),
            status_code: StatusCode::FORBIDDEN,
        })?,
        None => {
            return Err(AuthError {
                message: "Please add the JWT token to the header".to_string(),
                status_code: StatusCode::FORBIDDEN,
            })
        }
    };

    let header: Vec<&str> = auth_header.split_whitespace().collect();
    let token = header[1];

    let _token_data = match decode_jwt(token.to_string()) {
        Ok(data) => data,
        Err(_) => {
            return Err(AuthError {
                message: "Unable to decode token".to_string(),
                status_code: StatusCode::UNAUTHORIZED,
            })
        }
    };

    // Fetch the user details from the database
    let current_user = match retrieve_user_by_email() {
        Some(user) => user,
        None => {
            return Err(AuthError {
                message: "You are not an authorized user".to_string(),
                status_code: StatusCode::UNAUTHORIZED,
            })
        }
    };

    req.extensions_mut().insert(current_user);
    Ok(next.run(req).await)
}
