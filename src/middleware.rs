//! HTTP Authentication middleware.

use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;

use actix_service::{Service, Transform};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::Error;
use futures::future;
use futures::lock::Mutex;
use futures::Future;

use crate::extractors::{basic, bearer, AuthExtractor};
use futures::future::Ready;
use futures::task::{Context, Poll};
use pin_project::pin_project;

/// Middleware for checking HTTP authentication.
///
/// If there is no `Authorization` header in the request,
/// this middleware returns an error immediately,
/// without calling the `F` callback.
///
/// Otherwise, it will pass both the request and
/// the parsed credentials into it.
/// In case of successful validation `F` callback
/// is required to return the `ServiceRequest` back.
#[derive(Debug, Clone)]
pub struct HttpAuthentication<T, F>
where
    T: AuthExtractor,
{
    process_fn: Arc<F>,
    _extractor: PhantomData<T>,
}

impl<T, F, O> HttpAuthentication<T, F>
where
    T: AuthExtractor,
    F: Fn(ServiceRequest, T) -> O,
    O: Future<Output = Result<ServiceRequest, Error>> + 'static,
{
    /// Construct `HttpAuthentication` middleware
    /// with the provided auth extractor `T` and
    /// validation callback `F`.
    pub fn with_fn(process_fn: F) -> HttpAuthentication<T, F> {
        HttpAuthentication {
            process_fn: Arc::new(process_fn),
            _extractor: PhantomData,
        }
    }
}

impl<F, O> HttpAuthentication<basic::BasicAuth, F>
where
    F: Fn(ServiceRequest, basic::BasicAuth) -> O,
    O: Future<Output = Result<ServiceRequest, Error>> + 'static,
{
    /// Construct `HttpAuthentication` middleware for the HTTP "Basic"
    /// authentication scheme.
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use actix_web::Error;
    /// # use actix_web::dev::ServiceRequest;
    /// # use futures::future::{self, FutureResult};
    /// # use actix_web_httpauth::middleware::HttpAuthentication;
    /// # use actix_web_httpauth::extractors::basic::BasicAuth;
    /// // In this example validator returns immediately,
    /// // but since it is required to return anything
    /// // that implements `IntoFuture` trait,
    /// // it can be extended to query database
    /// // or to do something else in a async manner.
    /// fn validator(
    ///     req: ServiceRequest,
    ///     credentials: BasicAuth,
    /// ) -> FutureResult<ServiceRequest, Error> {
    ///     // All users are great and more than welcome!
    ///     future::ok(req)
    /// }
    ///
    /// let middleware = HttpAuthentication::basic(validator);
    /// ```
    pub fn basic(process_fn: F) -> Self {
        Self::with_fn(process_fn)
    }
}

impl<F, O> HttpAuthentication<bearer::BearerAuth, F>
where
    F: Fn(ServiceRequest, bearer::BearerAuth) -> O,
    O: Future<Output = Result<ServiceRequest, Error>> + 'static,
{
    /// Construct `HttpAuthentication` middleware for the HTTP "Bearer"
    /// authentication scheme.
    ///
    /// ## Example
    ///
    /// ```rust
    /// # use actix_web::Error;
    /// # use actix_web::dev::ServiceRequest;
    /// # use futures::future::{self, FutureResult};
    /// # use actix_web_httpauth::middleware::HttpAuthentication;
    /// # use actix_web_httpauth::extractors::bearer::{Config, BearerAuth};
    /// # use actix_web_httpauth::extractors::{AuthenticationError, AuthExtractorConfig};
    /// fn validator(req: ServiceRequest, credentials: BearerAuth) -> FutureResult<ServiceRequest, Error> {
    ///     if credentials.token() == "mF_9.B5f-4.1JqM" {
    ///         future::ok(req)
    ///     } else {
    ///         let config = req.app_data::<Config>()
    ///             .map(|data| data.get_ref().clone())
    ///             .unwrap_or_else(Default::default)
    ///             .scope("urn:example:channel=HBO&urn:example:rating=G,PG-13");
    ///
    ///         future::err(AuthenticationError::from(config).into())
    ///     }
    /// }
    ///
    /// let middleware = HttpAuthentication::bearer(validator);
    /// ```
    pub fn bearer(process_fn: F) -> Self {
        Self::with_fn(process_fn)
    }
}

impl<S, B, T, F, O> Transform<S> for HttpAuthentication<T, F>
where
    S: Service<
            Request = ServiceRequest,
            Response = ServiceResponse<B>,
            Error = Error,
        > + 'static,
    S::Future: 'static,
    F: Fn(ServiceRequest, T) -> O + 'static,
    O: Future<Output = Result<ServiceRequest, Error>> + 'static,
    T: AuthExtractor + 'static,
    <T as AuthExtractor>::Error: actix_http::error::ResponseError,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = AuthenticationMiddleware<S, F, T>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ok(AuthenticationMiddleware {
            service: Arc::new(Mutex::new(service)),
            process_fn: self.process_fn.clone(),
            _extractor: PhantomData,
        })
    }
}

#[doc(hidden)]
pub struct AuthenticationMiddleware<S, F, T>
where
    T: AuthExtractor,
{
    service: Arc<Mutex<S>>,
    process_fn: Arc<F>,
    _extractor: PhantomData<T>,
}

impl<S, B, F, T, O> Service for AuthenticationMiddleware<S, F, T>
where
    S: Service<
            Request = ServiceRequest,
            Response = ServiceResponse<B>,
            Error = Error,
        > + 'static,
    S::Future: 'static,
    F: Fn(ServiceRequest, T) -> O + 'static,
    O: Future<Output = Result<ServiceRequest, Error>> + 'static,
    T: AuthExtractor + 'static,
    <T as AuthExtractor>::Error: actix_http::error::ResponseError,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<ServiceResponse<B>, Error>>>>;

    fn poll_ready(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Result<(), Self::Error>> {
        self.service
            .try_lock()
            .expect("AuthenticationMiddleware was called already")
            .poll_ready(cx)
    }

    fn call(&mut self, req: Self::Request) -> Self::Future {
        let process_fn = self.process_fn.clone();
        // Note: cloning the mutex, not the service itself
        let inner = self.service.clone();

        let f = async move {
            let (req, credentials) = Extract::new(req).await?;
            let req = process_fn(req, credentials).await?;

            let mut service = inner.lock().await;
            service.call(req).await
        };

        Box::pin(f)
    }
}

#[pin_project]
struct Extract<T> {
    req: Option<Arc<ServiceRequest>>,
    #[allow(clippy::type_complexity)]
    f: Option<Pin<Box<dyn Future<Output = Result<T, Error>>>>>,
    _extractor: PhantomData<T>,
}

impl<T> Extract<T>
where
    T: AuthExtractor,
    T::Future: 'static,
    T::Error: 'static,
{
    pub fn new(req: ServiceRequest) -> Self {
        Extract {
            req: Some(Arc::new(req)),
            f: None,
            _extractor: PhantomData,
        }
    }
}

impl<T> Future for Extract<T>
where
    T: AuthExtractor,
    T::Future: 'static,
    T::Error: 'static,
    <T as AuthExtractor>::Error: actix_http::error::ResponseError,
{
    type Output = Result<(ServiceRequest, T), actix_http::error::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        if self.f.is_none() {
            let req = self
                .req
                .as_ref()
                .cloned()
                .expect("Extract future was polled twice!");

            let f = async move {
                let extractor = T::from_service_request(req.as_ref()).await;
                extractor.map_err(Into::into)
            };

            self.f = Some(Box::pin(f));
        }

        let f = self
            .f
            .as_mut()
            .expect("Extraction future should be initialized at this point")
            .as_mut();
        let credentials = futures::ready!(f.poll(cx));

        let req = self.req.take().expect("Extract future was polled twice!");
        let req = Arc::try_unwrap(req).expect("Ref still alive");

        let resp = credentials.map(|cred| (req, cred));

        Poll::Ready(resp)
    }
}
