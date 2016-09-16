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
}

impl RegisteredHeader {
    pub fn to_key(&self) -> &str {
        match *self {
            RegisteredHeader::Algorithm => "alg",
            RegisteredHeader::Type => "typ",
            RegisteredHeader::ContentType => "cty",
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
        let (header_str, payload_str, _signature_str) = try!{decode_segments(s)};
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

fn decode_segments(complete: &str) -> Result<(String, String, String), String> {
    let (header, payload, signature) = try!{split_segments(complete).map_err(|x| x.to_string())};
    let decoded_header = try!{decode_base_64(header)};
    let decoded_payload = try!{decode_base_64(payload)};
    let decoded_signature = try!{decode_base_64(signature)};
    Ok((decoded_header, decoded_payload, decoded_signature))
}

fn split_segments(complete: &str) -> Result<(&str, &str, &str), &'static str> {
    let parts: Vec<&str> = complete.split('.').collect();
    if parts.len() == 3 {
        Ok((parts[0], parts[1], parts[2]))
    } else {
        Err("The given String must split to 3 parts segmented by a dot each.")
    }
}

fn decode_base_64(what: &str) -> Result<String, String> {
    let bytes =
        try!{what.from_base64().map_err(|err| format!("Not a base64 encoded String: {}", err))};
    let string =
        try!{String::from_utf8(bytes).map_err(|err| format!("Not a valid UTF-8 String: {}", err))};
    Ok(string)
}
