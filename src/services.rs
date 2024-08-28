use crate::auth::CurrentUser;
use axum::{response::IntoResponse, Extension, Json};
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
struct UserResponse {
    email: String,
    first_name: String,
    last_name: String,
}

pub async fn hello(Extension(currentUser): Extension<CurrentUser>) -> impl IntoResponse {
    Json(UserResponse {
        email: currentUser.email,
        first_name: currentUser.first_name,
        last_name: currentUser.last_name,
    })
}
