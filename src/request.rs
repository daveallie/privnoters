use futures::{future, Future, Stream};
use hyper::{self, mime, Method, Client, Request, Uri};
use hyper::header::{Accept, Connection, ContentLength, ContentType, UserAgent, qitem};
use hyper_tls::HttpsConnector;
use std::error::Error;
use std::io;
use tokio_core::reactor::Core;
use url::form_urlencoded;

header! { (XRequestedWith, "X-Requested-With") => [String] }

pub fn post_privnote_data(data: &str) -> Result<String, Box<Error>> {
    let mut event_loop = Core::new()?;
    let handle = event_loop.handle();

    let client = Client::configure()
        .connector(HttpsConnector::new(4, &handle)?)
        .build(&handle);

    let uri = "https://privnote.com/legacy/".parse()?;
    let req = build_request(uri, data);

    let work = client.request(req).and_then(|res| {
        res.body()
            .fold(Vec::new(), |mut v, chunk| {
                v.extend(&chunk[..]);
                future::ok::<_, hyper::Error>(v)
            })
            .and_then(|chunks| {
                String::from_utf8(chunks).map_err(|_e| {
                    hyper::Error::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid Privnote response",
                    ))
                })
            })
    });

    let body = event_loop.run(work)?;
    Ok(body)
}

fn build_request(uri: Uri, data: &str) -> Request {
    let form_data = build_form_data(data);

    let mut req = Request::new(Method::Post, uri);
    req.headers_mut().set(ContentType::form_url_encoded());
    req.headers_mut().set(ContentLength(form_data.len() as u64));
    req.headers_mut().set(UserAgent::new(
        "privnoters (https://github.com/daveallie/privnoters)",
    ));
    req.headers_mut().set(Accept(
        vec![qitem(mime::APPLICATION_JSON), qitem(mime::STAR_STAR)],
    ));
    req.headers_mut().set(Connection::keep_alive());
    req.headers_mut().set(XRequestedWith(
        "XMLHttpRequest".to_string(),
    ));
    req.set_body(form_data);
    req
}

fn build_form_data(data: &str) -> String {
    form_urlencoded::Serializer::new(String::new())
        .append_pair("data", data)
        .append_pair("has_manual_pass", "false")
        .append_pair("duration_hours", "0")
        .append_pair("data_type", "T")
        .append_pair("dont_ask", "false")
        .append_pair("notify_email", "")
        .append_pair("notify_ref", "")
        .finish()
}
