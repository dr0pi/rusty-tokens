use std::collections::HashMap;
use std::str::FromStr;
use rustc_serialize::base64::FromBase64;
use rustc_serialize::json::Json;

pub mod planb;

pub enum Header<'a> {
    Registered(RegisteredHeader),
    Custom(&'a str),
}

pub enum RegisteredHeader {
    Algorithm,
    Type,
    ContentType,
    KeyId,
    JwkSetUrl,
    JsonWebKey,
    Critical,
    X509Url,
    X509CertificateChain,
    X509CertificateSha1Thumbprint,
}

impl RegisteredHeader {
    pub fn to_key(&self) -> &str {
        match *self {
            RegisteredHeader::Algorithm => "alg",
            RegisteredHeader::Type => "typ",
            RegisteredHeader::ContentType => "cty",
            RegisteredHeader::KeyId => "kid",
            RegisteredHeader::JwkSetUrl => "jku",
            RegisteredHeader::JsonWebKey => "jwk",
            RegisteredHeader::Critical => "crit",
            RegisteredHeader::X509Url => "x5u",
            RegisteredHeader::X509CertificateChain => "x5c",
            RegisteredHeader::X509CertificateSha1Thumbprint => "x5t",
        }
    }
}

pub enum Claim<'a> {
    Registered(RegisteredClaim),
    Custom(&'a str),
}

#[derive(PartialEq, Eq, Debug, Hash)]
pub enum RegisteredClaim {
    Subject,
    Audience,
    Issuer,
    ExpirationTime,
    IssuedAt,
    NotBefore,
    JwtId,
}

impl RegisteredClaim {
    pub fn to_key(&self) -> &str {
        match *self {
            RegisteredClaim::Subject => "sub",
            RegisteredClaim::Audience => "aud",
            RegisteredClaim::Issuer => "iss",
            RegisteredClaim::ExpirationTime => "exp",
            RegisteredClaim::IssuedAt => "iat",
            RegisteredClaim::NotBefore => "nbf",
            RegisteredClaim::JwtId => "jti",
        }
    }
}

pub struct JsonWebToken {
    pub header: HashMap<String, Json>,
    pub payload: HashMap<String, Json>,
}

impl JsonWebToken {
    pub fn new() -> JsonWebToken {
        JsonWebToken {
            header: HashMap::new(),
            payload: HashMap::new(),
        }
    }

    pub fn add_header(self, header: &Header, value: Json) -> Self {
        let mut x = self;
        let tag: String = match *header {
            Header::Registered(ref key) => String::from(key.to_key()),
            Header::Custom(ref key) => key.to_string(),
        };
        x.header.insert(tag, value);
        x
    }

    pub fn get_registered_header(&self, header: RegisteredHeader) -> Option<&Json> {
        self.get_header(&Header::Registered(header))
    }


    pub fn get_header(&self, header: &Header) -> Option<&Json> {
        match *header {
            Header::Registered(ref header) => self.header.get(header.to_key()),
            Header::Custom(key) => self.payload.get(key),
        }
    }


    pub fn add_payload(self, for_claim: &Claim, value: Json) -> Self {
        let mut x = self;
        let tag: String = match *for_claim {
            Claim::Registered(ref rclaim) => String::from(rclaim.to_key()),
            Claim::Custom(ref key) => key.to_string(),
        };
        x.payload.insert(tag, value);
        x
    }

    pub fn get_registered_payload(&self, for_claim: RegisteredClaim) -> Option<&Json> {
        self.get_payload(&Claim::Registered(for_claim))
    }

    pub fn get_payload(&self, for_claim: &Claim) -> Option<&Json> {
        match *for_claim {
            Claim::Registered(ref rclaim) => self.payload.get(rclaim.to_key()),
            Claim::Custom(key) => self.payload.get(key),
        }
    }
}

impl FromStr for JsonWebToken {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (header_str, payload_str) = try!{decode_data_segments(s)};
        let header = try!{parse_json_str_to_json_map(&header_str)};
        let payload = try!{parse_json_str_to_json_map(&payload_str)};
        Ok(JsonWebToken {
            header: header,
            payload: payload,
        })
    }
}

fn parse_json_str_to_json_map(json_str: &str) -> Result<HashMap<String, Json>, String> {
    let json_val = try!{Json::from_str(json_str).map_err(|x| x.to_string())};
    match json_val {
        Json::Object(obj) => {
            let mut the_map = HashMap::new();
            for (k, v) in obj.into_iter() {
                the_map.insert(k, v);
            }
            Ok(the_map)
        }
        _ => Err(String::from("Not a JSON object.")),
    }
}

fn decode_data_segments(complete: &str) -> Result<(String, String), String> {
    let (header, payload) = try!{extract_data_segments(complete).map_err(|x| x.to_owned())};
    let decoded_header = try!{decode_base_64_string(header)};
    let decoded_payload = try!{decode_base_64_string(payload)};
    Ok((decoded_header, decoded_payload))
}

fn extract_data_segments(complete: &str) -> Result<(&str, &str), &'static str> {
    let parts: Vec<&str> = complete.split('.').collect();
    if parts.len() == 3 {
        Ok((parts[0], parts[1]))
    } else {
        Err("The given String must split to 3 parts segmented by a dot each.")
    }
}

fn decode_base_64_bytes(what: &str) -> Result<Vec<u8>, String> {
    let bytes: Vec<u8> =
        try!{what.from_base64().map_err(|err| format!("No base64 encoded bytes: {}", err))};
    Ok(bytes)
}

fn decode_base_64_string(what: &str) -> Result<String, String> {
    let bytes: Vec<u8> = try!{decode_base_64_bytes(what)};
    let string =
        try!{String::from_utf8(bytes).map_err(|err| format!("basde64 bytes are not a valid UTF-8 String: {}", err))};
    Ok(string)
}

#[cfg(test)]
mod test {
    use jwt;

    const sample_token: &'static str = "eyJraWQiOiJ0ZXN0a2V5LWVzMjU2IiwiYWxnIjoiRVMyNTYifQ.\
                                        eyJzdWIiOiJ0ZXN0MiIsInNjb3BlIjpbImNuIl0sImlzcyI6IkIiLCJyZWFsbSI6Ii9zZXJ2aWNlcyIsImV4cCI6MTQ1NzMxOTgxNCwiaWF0IjoxNDU3MjkxMDE0fQ.\
                                        KmDsVB09RAOYwT0Y6E9tdQpg0rAPd8SExYhcZ9tXEO6y9AWX4wBylnmNHVoetWu7MwoexWkaKdpKk09IodMVug";

    const sample_header_json: &'static str = "{\"kid\":\"testkey-es256\",\"alg\":\"ES256\"}";
    const sample_payload_json: &'static str = "{\"sub\":\"test2\",\"scope\":[\"cn\"],\"iss\":\
                                               \"B\",\"realm\":\"/services\",\"exp\":1457319814,\
                                               \"iat\":1457291014}";

    #[test]
    fn must_decode_base_64_header_to_a_string() {
        let sample = "eyJraWQiOiJ0ZXN0a2V5LWVzMjU2IiwiYWxnIjoiRVMyNTYifQ";
        let result = jwt::decode_base_64_string(sample).unwrap();
        assert_eq!(sample_header_json, result);
    }

    #[test]
    fn must_decode_base_64_payload_to_a_string() {
        let sample = "eyJzdWIiOiJ0ZXN0MiIsInNjb3BlIjpbImNuIl0sImlzcyI6IkIiLCJyZWFsbSI6Ii9zZXJ2aWNlcyIsImV4cCI6MTQ1NzMxOTgxNCwiaWF0IjoxNDU3MjkxMDE0fQ";
        let result = jwt::decode_base_64_string(sample).unwrap();
        assert_eq!(sample_payload_json, result);
    }

    #[test]
    fn split_data_segments_must_work() {
        let sample = sample_token;
        let expected = ("eyJraWQiOiJ0ZXN0a2V5LWVzMjU2IiwiYWxnIjoiRVMyNTYifQ",
                        "eyJzdWIiOiJ0ZXN0MiIsInNjb3BlIjpbImNuIl0sImlzcyI6IkIiLCJyZWFsbSI6Ii9zZXJ2aWNlcyIsImV4cCI6MTQ1NzMxOTgxNCwiaWF0IjoxNDU3MjkxMDE0fQ");

        let result = jwt::extract_data_segments(sample).unwrap();

        assert_eq!(expected, result);
    }

    #[test]
    fn decode_data_segments_must_work() {
        let sample = sample_token;
        let expected = (sample_header_json.to_owned(), sample_payload_json.to_owned());

        let result = jwt::decode_data_segments(sample).unwrap();

        assert_eq!(expected, result);
    }

}
