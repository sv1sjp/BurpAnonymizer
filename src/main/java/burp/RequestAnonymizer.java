// SPDX-License-Identifier: GPL-3.0-only
// SPDX-FileCopyrightText: 2026 Dimitris Vagiakakos @sv1sjp <https://www.tuxhouse.eu>
package burp;

import java.util.*;
import java.util.regex.*;

/**
 * Burp Request Anonymizer - Core Anonymization Engine (v3)
 *
 * Developed by Dimitris Vagiakakos @sv1sjp
 * https://www.tuxhouse.eu
 * A Burp Suite extension that automatically redacts **PII, credentials, and sensitive identifiers** from HTTP traffic.   
*/
public class RequestAnonymizer {

    private final IExtensionHelpers helpers;
    private final String originalHost;
    private final int originalPort;
    private final String originalProtocol;

    // Consistent mapping stores
    private final Map<String, String> hostMap = new LinkedHashMap<>();
    private final Map<String, String> cookieNameMap = new LinkedHashMap<>();
    private final Map<String, String> cookieValueMap = new LinkedHashMap<>();
    private final Map<String, String> headerValueMap = new LinkedHashMap<>();
    private final Map<String, String> paramValueMap = new LinkedHashMap<>();
    private final Map<String, String> uuidMap = new LinkedHashMap<>();
    private final Map<String, String> ipMap = new LinkedHashMap<>();
    private final Map<String, String> emailMap = new LinkedHashMap<>();
    private final Map<String, String> jwtMap = new LinkedHashMap<>();
    private final Map<String, String> base64Map = new LinkedHashMap<>();
    private final Map<String, String> nonceMap = new LinkedHashMap<>();
    private final Map<String, String> etagMap = new LinkedHashMap<>();
    private final Map<String, String> hexTokenMap = new LinkedHashMap<>();
    private final Map<String, String> usernameMap = new LinkedHashMap<>();
    // v3 mapping stores
    private final Map<String, String> panMap = new LinkedHashMap<>();
    private final Map<String, String> ibanMap = new LinkedHashMap<>();
    private final Map<String, String> phoneMap = new LinkedHashMap<>();
    private final Map<String, String> ssnMap = new LinkedHashMap<>();
    private final Map<String, String> govIdMap = new LinkedHashMap<>();
    private final Map<String, String> coordMap = new LinkedHashMap<>();
    private final Map<String, String> addressMap = new LinkedHashMap<>();

    // Counters for generating sequential placeholders
    private int hostCounter = 1;
    private int cookieNameCounter = 1;
    private int cookieValueCounter = 1;
    private int tokenCounter = 1;
    private int paramCounter = 1;
    private int uuidCounter = 1;
    private int ipCounter = 1;
    private int emailCounter = 1;
    private int jwtCounter = 1;
    private int secretCounter = 1;
    private int base64Counter = 1;
    private int nonceCounter = 1;
    private int etagCounter = 1;
    private int hexTokenCounter = 1;
    private int usernameCounter = 1;
    private int panCounter = 1;
    private int ibanCounter = 1;
    private int phoneCounter = 1;
    private int ssnCounter = 1;
    private int govIdCounter = 1;
    private int coordCounter = 1;
    private int addressCounter = 1;
    private final Map<String, String> genericIdMap = new LinkedHashMap<>();
    private int genericIdCounter = 1;
    private final Map<String, String> numericIdMap = new LinkedHashMap<>();
    private int numericIdCounter = 1;
    private final Map<String, String> paspMap = new LinkedHashMap<>();
    private int paspCounter = 1;
    private final Map<String, String> nricSgMap = new LinkedHashMap<>();
    private int nricSgCounter = 1;
    private final Map<String, String> tfnAuMap = new LinkedHashMap<>();
    private int tfnAuCounter = 1;
    private final Map<String, String> ahvChMap = new LinkedHashMap<>();
    private int ahvChCounter = 1;
    private final Map<String, String> peselPlMap = new LinkedHashMap<>();
    private int peselPlCounter = 1;

    // ==================== SENSITIVE HEADER NAMES ====================

    private static final Set<String> SENSITIVE_HEADERS = new HashSet<>(Arrays.asList(
        "authorization", "proxy-authorization",
        "cookie", "set-cookie", "set-cookie2",
        "x-auth-token", "x-api-key", "x-api-secret",
        "x-csrf-token", "x-xsrf-token", "x-request-id",
        "x-correlation-id", "x-session-id", "x-trace-id",
        "x-forwarded-for", "x-real-ip", "x-client-ip",
        "x-originating-ip", "x-remote-ip", "x-remote-addr",
        "x-forwarded-host", "x-forwarded-server",
        "true-client-ip", "cf-connecting-ip",
        "x-amz-security-token", "x-amz-credential",
        "x-ms-client-principal", "x-ms-token-aad-access-token",
        "x-shopify-access-token", "x-stripe-client-info",
        "x-api-token", "x-access-token", "x-refresh-token",
        "x-device-id", "x-installation-id",
        "x-user-id", "x-account-id", "x-tenant-id",
        "x-custom-auth", "x-secret", "x-token",
        "origin", "referer",
        "requesttoken",
        "x-debug-token", "x-debug-token-link",
        "origin-trial",
        "deviceid",
        "x-deviceid", "x-device-fingerprint",
        "x-oc-mtime", "x-oc-etag",
        "oc-etag", "oc-fileid", "oc-checksum",
        "x-nc-token", "x-nc-session",
        "x-owncloud-token", "x-nextcloud-token",
        "sec-websocket-key", "sec-websocket-accept",
        "x-api-signature", "x-signature",
        "x-hmac-signature", "x-webhook-signature",
        "x-hub-signature", "x-hub-signature-256",
        "x-user-id", "x-customer-id", "x-employee-id",
        "x-member-id", "x-patient-id", "x-subscriber-id",
        "x-citizen-id", "x-resident-id", "x-person-id",
        "x-contact-id", "x-profile-id", "x-applicant-id",
        "x-client-id", "x-partner-id", "x-vendor-id",
        "x-merchant-id", "x-seller-id", "x-buyer-id",
        "x-student-id", "x-teacher-id", "x-staff-id",
        "x-agent-id", "x-operator-id", "x-principal-id",
        "x-payment-token", "x-card-token", "x-bank-token",
        "x-transaction-id", "x-order-id", "x-invoice-id",
        "x-booking-id", "x-reservation-id", "x-ticket-id",
        "x-receipt-id", "x-claim-id", "x-policy-id",
        "x-benefit-id", "x-case-id",
        "x-tracking-id", "x-reference-id", "x-external-id",
        "x-internal-id", "x-batch-id", "x-job-id",
        "x-run-id", "x-flow-id", "x-pipeline-id",
        "x-request-token", "x-idempotency-key",
        "x-geo-location", "x-gps-coordinates",
        "x-lat", "x-lng", "x-latitude", "x-longitude",
        "x-ssn", "x-national-id", "x-tax-id", "x-tin",
        "x-passport-id", "x-license-id", "x-licence-id",
        "x-insurance-id", "x-health-id", "x-nhs-number",
        "x-medicare-id", "x-medicaid-id"
    ));

    // Headers whose values are ETag-like (quoted hex hashes)
    private static final Set<String> ETAG_HEADERS = new HashSet<>(Arrays.asList(
        "etag", "if-none-match", "if-match",
        "oc-etag", "x-oc-etag"
    ));

    // ==================== SENSITIVE PARAM NAMES ====================

    private static final Set<String> SENSITIVE_PARAMS = new HashSet<>(Arrays.asList(
        // === Authentication / Authorization ===
        "password", "passwd", "pass", "pwd", "secret",
        "token", "access_token", "refresh_token", "id_token",
        "api_key", "apikey", "api-key", "app_key", "app_secret",
        "client_secret", "client_id",
        "auth", "auth_token", "authentication",
        "session", "sessionid", "session_id", "sid",
        "key", "private_key", "signing_key", "encryption_key",
        "csrf", "csrf_token", "_token", "nonce",
        "x-csrf-token", "x-xsrf-token",
        "code", "grant_code", "authorization_code",
        "aws_access_key_id", "aws_secret_access_key",
        "pin", "otp", "totp", "mfa_code", "verification_code",
        "requesttoken", "data-requesttoken",
        "fingerprint", "device_fingerprint",

        // === Personal identity ===
        "username", "user_name", "login", "user",
        "displayname", "display_name", "display-name",
        "firstname", "first_name", "first-name",
        "lastname", "last_name", "last-name",
        "middlename", "middle_name", "middle-name",
        "fullname", "full_name", "full-name",
        "name", "realname", "real_name", "nickname",
        "maiden_name", "birth_name",
        "prefix", "suffix", "salutation", "title",
        "gender", "sex",

        // === Contact details ===
        "email", "e-mail", "mail",
        "email_address", "emailaddress",
        "phone", "telephone", "mobile", "cell",
        "phone_number", "phonenumber", "phone-number",
        "mobile_number", "mobilenumber",
        "cell_phone", "cellphone",
        "home_phone", "work_phone", "office_phone",
        "fax", "fax_number", "faxnumber",
        "msisdn", "calling_number", "callingnumber",
        "sms", "sms_number",

        // === Physical address ===
        "address", "street", "street_address", "street-address",
        "address1", "address2", "address_line1", "address_line2",
        "city", "town", "municipality",
        "state", "province", "region", "county",
        "zip", "zipcode", "zip_code", "zip-code",
        "postal", "postalcode", "postal_code", "postal-code",
        "postcode", "post_code",
        "country",
        "latitude", "lat",
        "longitude", "lng", "lon", "long",
        "coordinates", "coords", "geo", "geolocation",
        "geo_location", "gps", "location",
        "place_of_birth", "birthplace",

        // === Date of birth / Age ===
        "dob", "date_of_birth", "birthday", "birth_date",
        "birthdate", "dateofbirth",
        "age",

        // === Financial / Banking ===
        "credit_card", "creditcard", "cc_number", "ccnumber",
        "card_number", "cardnumber", "card-number",
        "account_number", "accountnumber", "account-number",
        "routing_number", "routingnumber", "routing-number",
        "iban", "swift", "bic", "swift_code", "bic_code",
        "bank_account", "bankaccount",
        "sort_code", "sortcode", "sort-code",
        "aba", "aba_number",
        "clabe",  // Mexico
        "bsb",    // Australia
        "ifsc",   // India

        // === Credit/Debit card details ===
        "cvv", "cvc", "cvv2", "cvc2", "cid",
        "card_cvv", "cardcvv", "card_cvc", "cardcvc",
        "security_code", "securitycode", "security-code",
        "card_verification", "verification_value",
        "expiry", "expiry_date", "expirydate", "expiry-date",
        "exp_date", "expdate",
        "expiration", "expiration_date", "expirationdate",
        "exp_month", "expmonth", "exp_year", "expyear",
        "card_expiry", "cardexpiry",
        "card_holder", "cardholder", "card_name", "cardname",
        "name_on_card", "nameoncard",
        "card_type", "cardtype", "card-type",
        "pan", "primary_account_number",
        "card_bin", "bin",

        // === Government IDs / National IDs ===
        "ssn", "social_security", "social_security_number",
        "national_id", "nationalid", "national-id",
        "national_id_number", "national_identification",
        "tax_id", "taxid", "tax-id",
        "tax_number", "taxnumber", "tax_identification",
        "tin", "tax_identification_number",
        "vat", "vat_number", "vatnumber",
        "ein",  // Employer Identification Number
        "itin", // Individual Taxpayer ID

        // Country-specific government IDs
        "sin", "social_insurance_number",   // Canada SIN
        "nin", "national_insurance_number", // UK NIN / NINO
        "nino",
        "pps", "ppsn", "pps_number",       // Ireland PPS
        "bsn",                               // Netherlands BSN
        "personnummer", "personnumber",      // Sweden/Norway
        "cpr", "cpr_number",                // Denmark CPR
        "hetu",                              // Finland HETU
        "pesel",                             // Poland PESEL
        "nif", "nie",                        // Spain NIF/NIE
        "codice_fiscale", "cf",             // Italy
        "amka",                              // Greece AMKA
        "afm",                               // Greece AFM
        "tc_kimlik", "tckimlik", "tc_no", "tc_kimlik_no", // Turkey TC Kimlik
        "emirates_id", "emiratesid", "emirates-id",         // UAE
        "saudi_id", "saudid", "iqama", "iqama_number",     // Saudi Arabia
        "qatar_id", "qatarid", "qid",                       // Qatar
        "bahrain_id", "cpr_bahrain",                        // Bahrain
        "kuwait_id", "civil_id",                            // Kuwait
        "oman_id",                                           // Oman
        "aadhaar", "aadhar",                                // India Aadhaar
        "pan_india", "pan_card",                            // India PAN card
        "cpf",                                               // Brazil CPF
        "rut", "run",                                        // Chile RUT/RUN
        "curp", "rfc",                                       // Mexico CURP/RFC
        "cedula",                                            // Colombia/various LatAm

        // === Passport / Travel documents ===
        "passport", "passport_number", "passportnumber", "passport-number",
        "passport_no", "passport_id",
        "travel_document", "travel_doc",
        "visa_number", "visa_no", "visa",

        // === Driver licence ===
        "driver_licence", "driverlicence", "driver-licence",
        "driving_licence", "drivinglicence", "driving-licence",
        "driver_license", "driverlicense", "driver-license",
        "driving_license", "drivinglicense", "driving-license",
        "licence_number", "license_number",
        "dl_number", "dlnumber",

        // === Health / Medical (GDPR Article 9) ===
        "patient_id", "patientid", "patient-id",
        "medical_record", "medical_record_number", "mrn",
        "health_id", "healthid", "health-id",
        "health_card", "healthcard", "health-card",
        "insurance_id", "insuranceid", "insurance-id",
        "insurance_number", "insurance_policy",
        "policy_number", "policynumber", "policy-number",
        "member_id", "memberid", "member-id",
        "subscriber_id", "subscriberid", "subscriber-id",
        "group_number", "groupnumber",
        "nhs_number", "nhsnumber", "nhs-number",   // UK NHS
        "ehic", "ehic_number",                       // EU Health Insurance Card
        "medicare", "medicare_number", "medicarenumber",
        "medicaid", "medicaid_number",
        "hic", "hic_number",                         // Health Insurance Claim
        "diagnosis", "diagnosis_code",
        "icd_code", "icd10", "icd9",
        "prescription", "prescription_id",
        "medication", "drug_name",
        "blood_type", "bloodtype",
        "allergy", "allergies",
        "disability", "handicap",
        "biometric", "biometric_data",
        "dna", "genetic", "genome",

        // === Education ===
        "student_id", "studentid", "student-id",
        "student_number", "studentnumber",
        "matriculation", "matriculation_number", "matrikelnummer",
        "enrollment_id", "enrollment_number",
        "school_id", "university_id",
        "teacher_id", "teacherid",
        "faculty_id",

        // === Employment ===
        "employee_id", "employeeid", "employee-id",
        "employee_number", "employeenumber",
        "staff_id", "staffid", "staff-id",
        "staff_number", "staffnumber",
        "badge_id", "badgeid", "badge-id",
        "badge_number", "badgenumber",
        "payroll_id", "payroll_number",
        "worker_id", "personnel_id", "personnel_number",
        "salary", "wage", "compensation", "income",

        // === Order / Transaction / Booking IDs ===
        "order_id", "orderid", "order-id",
        "order_number", "ordernumber", "order-number",
        "transaction_id", "transactionid", "transaction-id",
        "transaction_number",
        "booking_id", "bookingid", "booking-id",
        "booking_number", "bookingnumber", "booking-number",
        "booking_reference", "bookingreference",
        "reservation_id", "reservationid",
        "reservation_number", "reservationnumber",
        "confirmation_number", "confirmationnumber",
        "reference_number", "referencenumber", "reference-number",
        "tracking_number", "trackingnumber", "tracking-number",
        "tracking_id", "trackingid",
        "shipment_id", "shipment_number",
        "invoice_id", "invoiceid", "invoice-id",
        "invoice_number", "invoicenumber", "invoice-number",
        "receipt_id", "receipt_number",
        "ticket_id", "ticketid", "ticket-id",
        "ticket_number", "ticketnumber", "ticket-number",
        "case_id", "caseid", "case-id",
        "case_number", "casenumber", "case-number",
        "claim_id", "claimid", "claim-id",
        "claim_number", "claimnumber",
        "benefit_case_id", "benefit_id",
        "application_id", "application_number",
        "contract_id", "contract_number",
        "agreement_id", "agreement_number",
        "pnr", "record_locator",                    // airline PNR

        // === Utility / Service provider IDs ===
        "account_id", "accountid", "account-id",
        "customer_id", "customerid", "customer-id",
        "customer_number", "customernumber",
        "subscriber_number",
        "utility_account", "meter_number", "meternumber",
        "service_id", "service_number",
        "contract_number", "supply_number",

        // === Device / Hardware IDs ===
        "deviceid", "device_id", "device-id",
        "device_token", "devicetoken",
        "device_name", "devicename",
        "serial_number", "serialnumber", "serial-number",
        "imei", "imei_number",
        "imsi",
        "mac_address", "macaddress", "mac-address",
        "hardware_id", "hw_id",
        "machine_id", "machineid",

        // === Secrets / Cryptographic ===
        "private_key", "public_key",
        "secret_key", "symmetric_key",
        "hmac_secret", "hmac_key",
        "signing_secret", "webhook_secret",
        "encryption_key", "decryption_key",
        "master_key", "recovery_key",
        "ssh_key", "pgp_key", "gpg_key",

        // === Added for more comprehensive pattern tracking ===
        "drivers_license", "room", "roomnumber", "tracking", "phone_ext", "fax_ext",
        "barcode", "internalbarcode", "ext", "extension",
        // Generalized base tokens for partial matching
        "pasp", "nric", "tfn", "ahv", "pesel", "hcard", "health", "tax", "nino", "ssn", "sin",
        "pan", "iban", "passport", "emirates", "kimlik", "iqama", "qid", "aadhaar", "ticket",
        "roomno", "pin_code", "ext_code", "ref_id", "filename", "logfile", "stree", "addr", "telefone",
        // Extra short-prefix tokens for fuzzy key detection
        "barc", "eid", "emir", "full", "mrt", "mrz", "idno", "idnum", "natid", "govid",
        "drvlic", "drv", "lic", "crd", "card", "num", "reg"
    ));

    private static final Set<String> FULL_REDACT_KEYS = new HashSet<>(Arrays.asList(
        "notes", "comments", "description", "body", "subject"
    ));

    // ==================== REGEX PATTERNS ====================

    private static final Pattern JWT_PATTERN = Pattern.compile(
        "eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]*");

    private static final Pattern UUID_PATTERN = Pattern.compile(
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    private static final Pattern IPV4_PATTERN = Pattern.compile(
        "\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b");

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
        "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}");

    private static final Pattern AWS_KEY_PATTERN = Pattern.compile(
        "(?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA|AIPA)[A-Z0-9]{16}");

    private static final Pattern BEARER_PATTERN = Pattern.compile(
        "(Bearer\\s+)(\\S+)", Pattern.CASE_INSENSITIVE);

    private static final Pattern BASIC_PATTERN = Pattern.compile(
        "(Basic\\s+)(\\S+)", Pattern.CASE_INSENSITIVE);

    private static final Pattern DIGEST_PATTERN = Pattern.compile(
        "(Digest\\s+)(.*)", Pattern.CASE_INSENSITIVE);

    private static final Pattern NTLM_PATTERN = Pattern.compile(
        "(NTLM\\s+)(\\S+)", Pattern.CASE_INSENSITIVE);

    private static final Pattern NEGOTIATE_PATTERN = Pattern.compile(
        "(Negotiate\\s+)(\\S+)", Pattern.CASE_INSENSITIVE);

    private static final Pattern AWS_SIGV4_PATTERN = Pattern.compile(
        "(AWS4-HMAC-SHA256\\s+)(.*)", Pattern.CASE_INSENSITIVE);

    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
        "(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\\-]*[a-zA-Z0-9])?" +
        "(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9\\-]*[a-zA-Z0-9])?)*\\.[a-zA-Z]{2,})");

    // HTML attribute patterns for sensitive data
    private static final Pattern DATA_USER_ATTR = Pattern.compile(
        "(data-user\\s*=\\s*\")([^\"]+)(\")", Pattern.CASE_INSENSITIVE);

    private static final Pattern DATA_DISPLAYNAME_ATTR = Pattern.compile(
        "(data-user-displayname\\s*=\\s*\")([^\"]+)(\")", Pattern.CASE_INSENSITIVE);

    private static final Pattern DATA_REQUESTTOKEN_ATTR = Pattern.compile(
        "(data-requesttoken\\s*=\\s*\")([^\"]+)(\")", Pattern.CASE_INSENSITIVE);

    private static final Pattern NONCE_ATTR = Pattern.compile(
        "(nonce\\s*=\\s*\")([^\"]+)(\")", Pattern.CASE_INSENSITIVE);

    private static final Pattern DATA_URI_BASE64 = Pattern.compile(
        "(data:[a-zA-Z0-9/+\\-]+;base64,)([A-Za-z0-9+/=]+)");

    private static final Pattern DATA_BTMANIFEST_ATTR = Pattern.compile(
        "(data-btmanifest\\s*=\\s*\")([^\"]+)(\")", Pattern.CASE_INSENSITIVE);

    private static final Pattern DATA_SENSITIVE_ATTR = Pattern.compile(
        "(data-(?:[a-z\\-]*(?:token|session|nonce|secret|key|auth|credential|fingerprint|device)[a-z\\-]*)\\s*=\\s*\")([^\"]+)(\")",
        Pattern.CASE_INSENSITIVE);

    // ETag values: "hex_string" or W/"hex_string"
    private static final Pattern ETAG_VALUE_PATTERN = Pattern.compile(
        "(?:W/)?\"([0-9a-fA-F]{8,})\"");

    // Long base64 strings with delimiter context
    private static final Pattern LONG_BASE64_PATTERN = Pattern.compile(
        "(?<=[=\":\\s,;>]|^)[A-Za-z0-9+/]{20,}[=]{0,2}(?::[A-Za-z0-9+/]{20,}[=]{0,2})*(?=[\"\\s,;<&]|$)");

    // Hex tokens (24+ hex chars)
    private static final Pattern HEX_TOKEN_PATTERN = Pattern.compile(
        "\\b[0-9a-fA-F]{24,}\\b");

    // Alphanumeric tokens (20+ mixed chars)
    private static final Pattern ALPHANUM_TOKEN_PATTERN = Pattern.compile(
        "\\b[A-Za-z0-9_-]{20,}\\b");

    // Oc-Fileid pattern
    private static final Pattern OC_FILEID_PATTERN = Pattern.compile(
        "\\b[0-9]{5,}[a-z]{4,}[0-9a-z]+\\b");

    // <title>Content</title>
    private static final Pattern HTML_TITLE_PATTERN = Pattern.compile(
        "(<title[^>]*>)(.*?)(</title>)", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);


    // ==================== PATTERNS: FINANCIAL ====================

    // PAN / Credit Card: 13-19 digit sequences (with optional spaces/dashes)
    // Matches: 4111111111111111, 4111 1111 1111 1111, 4111-1111-1111-1111
    private static final Pattern PAN_PATTERN = Pattern.compile(
        "\\b([3-6]\\d{3})[\\s\\-]?(\\d{4})[\\s\\-]?(\\d{4})[\\s\\-]?(\\d{1,7})\\b");

    // IBAN: 2 letters + 2 digits + 8-30 alphanumeric (with optional spaces)
    // Matches: GB29NWBK60161331926819, GB29 NWBK 6016 1331 9268 19
    private static final Pattern IBAN_PATTERN = Pattern.compile(
        "\\b([A-Z]{2}\\d{2})[\\s]?([A-Z0-9]{4})[\\s]?([A-Z0-9]{4})[\\s]?([A-Z0-9]{4})[\\s]?([A-Z0-9]{0,4})[\\s]?([A-Z0-9]{0,4})[\\s]?([A-Z0-9]{0,4})[\\s]?([A-Z0-9]{0,4})[\\s]?([A-Z0-9]{0,2})\\b",
        Pattern.CASE_INSENSITIVE);

    // Simpler IBAN: catch compact IBANs (no spaces) - 2 letters + 2 digits + 8-30 alnum
    private static final Pattern IBAN_COMPACT_PATTERN = Pattern.compile(
        "\\b[A-Z]{2}\\d{2}[A-Z0-9]{8,30}\\b", Pattern.CASE_INSENSITIVE);

    // SWIFT/BIC: 8 or 11 characters (BANKCCLL or BANKCCLLBBB)
    private static final Pattern SWIFT_BIC_PATTERN = Pattern.compile(
        "\\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\\b");

    // ==================== PATTERNS: GOVERNMENT IDs ====================

    // US SSN: 3 digits - 2 digits - 4 digits (XXX-XX-XXXX)
    private static final Pattern SSN_PATTERN = Pattern.compile(
        "\\b(?!000|666|9\\d{2})(\\d{3})[\\s\\-\\u2011\\u2012\\u2013\\u2014](\\d{2})[\\s\\-\\u2011\\u2012\\u2013\\u2014](\\d{4})\\b");

    // Canada SIN: 9 digits with optional spaces/dashes (XXX-XXX-XXX or XXX XXX XXX)
    private static final Pattern SIN_PATTERN = Pattern.compile(
        "\\b(\\d{3})[\\s\\-\\u2011\\u2012\\u2013\\u2014](\\d{3})[\\s\\-\\u2011\\u2012\\u2013\\u2014](\\d{3})\\b");

    // UK National Insurance Number (NIN/NINO): 2 letters + 6 digits + 1 letter
    private static final Pattern NIN_PATTERN = Pattern.compile(
        "\\b[A-CEGHJ-PR-TW-Z]{2}[\\s]?\\d{2}[\\s]?\\d{2}[\\s]?\\d{2}[\\s]?[A-D]\\b",
        Pattern.CASE_INSENSITIVE);

    // UAE Emirates ID: 784-YYYY-NNNNNNN-C (15 digits)
    private static final Pattern EMIRATES_ID_PATTERN = Pattern.compile(
        "\\b784[\\s\\-]?\\d{4}[\\s\\-]?\\d{7}[\\s\\-]?\\d\\b");

    // Turkish TC Kimlik: exactly 11 digits starting with non-zero
    private static final Pattern TC_KIMLIK_PATTERN = Pattern.compile(
        "\\b[1-9]\\d{10}\\b");

    // Saudi National ID / Iqama: 10 digits starting with 1 (citizen) or 2 (resident)
    private static final Pattern SAUDI_ID_PATTERN = Pattern.compile(
        "\\b[12]\\d{9}\\b");

    // Qatar QID: 11 digits starting with 2 or 3
    private static final Pattern QATAR_ID_PATTERN = Pattern.compile(
        "\\b[23]\\d{10}\\b");

    // India Aadhaar: 12 digits with optional spaces (XXXX XXXX XXXX)
    private static final Pattern AADHAAR_PATTERN = Pattern.compile(
        "\\b[2-9]\\d{3}[\\s]?\\d{4}[\\s]?\\d{4}\\b");

    // Passports
    private static final Pattern PASSPORT_PATTERN = Pattern.compile(
        "\\b[A-Z]{0,2}\\d{7,9}[A-Z]?\\b", Pattern.CASE_INSENSITIVE);

    // Singapore NRIC
    private static final Pattern NRIC_SG_PATTERN = Pattern.compile(
        "\\b[STFGM]\\d{7}[A-Z]\\b", Pattern.CASE_INSENSITIVE);

    // Australia TFN
    private static final Pattern TFN_AU_PATTERN = Pattern.compile(
        "\\b\\d{3}[\\.\\-\\s]?\\d{3}[\\.\\-\\s]?\\d{3}\\b");

    // Swiss AHV
    private static final Pattern AHV_CH_PATTERN = Pattern.compile(
        "\\b756\\.\\d{4}\\.\\d{4}\\.\\d{2}\\b");

    // Poland PESEL
    private static final Pattern PESEL_PL_PATTERN = Pattern.compile(
        "\\b\\d{11}\\b");

    // Generic Alphanumeric IDs (1-2 letters + 6-10 digits)
    private static final Pattern ALPHANUM_ID_PATTERN = Pattern.compile(
        "\\b[A-Za-z]{1,2}\\d{6,10}[A-Za-z]?\\b");

    // Generic Multi-format structures to catch unstructured edges unconditionally
    private static final Pattern LOCAL_PHONE_PATTERN = Pattern.compile(
        "\\b\\d{3}[\\.\\-\\s]\\d{4}\\b");
    private static final Pattern PREFIX_6_ALPHANUM_PATTERN = Pattern.compile(
        "\\b\\d{6}[\\.\\-\\s][A-Za-z0-9]{4,5}\\b");
    private static final Pattern GROUPED_11_PATTERN = Pattern.compile(
        "\\b\\d{6}[\\.\\-\\s]?\\d{3}[\\.\\-\\s]?\\d{2}\\b");
    private static final Pattern RELAXED_UAE_ID_PATTERN = Pattern.compile(
        "\\b784[\\.\\-\\s]?\\d{4}[\\.\\-\\s]?\\d{4,7}[\\.\\-\\s]?\\d{1,4}\\b");

    // ==================== PATTERNS: PHONE NUMBERS ====================

    // E.164 international: +<country_code><number> (7-15 digits)
    private static final Pattern PHONE_E164_PATTERN = Pattern.compile(
        "\\+[1-9]\\d{6,14}\\b");

    // International with separators: +1-234-567-8901, +44 20 7946 0958
    private static final Pattern PHONE_INTL_PATTERN = Pattern.compile(
        "\\+[1-9][\\d\\s\\-\\.\\(\\)]{6,20}\\d");

    // US/CA format: (123) 456-7890 or 123-456-7890
    private static final Pattern PHONE_US_PATTERN = Pattern.compile(
        "\\(?\\d{3}\\)?[\\s\\-\\.]?\\d{3}[\\s\\-\\.]?\\d{4}\\b");

    // ==================== PATTERNS: GPS / COORDINATES ====================

    // Decimal coordinates: 40.7128, -74.0060 or lat=40.7128&lon=-74.0060
    private static final Pattern COORD_DECIMAL_PATTERN = Pattern.compile(
        "\\b-?(?:[1-8]?\\d(?:\\.\\d{4,})|90(?:\\.0{4,}))\\s*[,;]\\s*-?(?:1[0-7]\\d(?:\\.\\d{4,})|0?\\d{1,2}(?:\\.\\d{4,})|180(?:\\.0{4,}))\\b");

    // Standalone latitude/longitude values with 4+ decimal places (high precision = likely real coordinates)
    private static final Pattern COORD_SINGLE_PATTERN = Pattern.compile(
        "\\b-?(?:1[0-8]\\d|0?\\d{1,2})\\.\\d{5,}\\b");

    // ==================== v3 PATTERNS: EU POSTAL CODES ====================
    // (Additional postal code patterns beyond what zip/postal key matching catches)
    // UK postcodes: SW1A 1AA format
    private static final Pattern UK_POSTCODE_PATTERN = Pattern.compile(
        "\\b[A-Z]{1,2}\\d[A-Z0-9]?\\s?\\d[A-Z]{2}\\b", Pattern.CASE_INSENSITIVE);

    private static final Pattern GENERIC_ADDRESS_PATTERN = Pattern.compile(
        "\\b\\d{1,5}(?:-\\d{1,5})?[a-zA-Z]?\\s+(?:[a-zA-Z]+\\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Way|Square|Sq|Court|Ct|Plaza|Pl|Terrace|Ter|Alley|Aly|Trail|Trl|Highway|Hwy|Parkway|Pkwy)\\b\\.?", Pattern.CASE_INSENSITIVE);

    private static final Pattern GENERIC_ID_PATTERN = Pattern.compile(
        "\\b[A-Z]{3,5}-\\d{3,}\\b");

    private static final Pattern LOOSE_PHONE_PATTERN = Pattern.compile(
        "\\b0{0,2}\\d{10,15}(?:x\\d{1,4})?\\b");


    // ==================== CONSTRUCTOR ====================

    public RequestAnonymizer(IExtensionHelpers helpers, String originalHost, int port, String protocol) {
        this.helpers = helpers;
        this.originalHost = originalHost;
        this.originalPort = port;
        this.originalProtocol = protocol;

        // Pre-map the primary host
        hostMap.put(originalHost.toLowerCase(), "target.tuxexample.com");
        hostCounter++;
    }

    // ==================== PUBLIC API ====================

    /**
     * Anonymize a full HTTP request (headers + body).
     */
    public String anonymizeRequest(byte[] rawRequest) {
        IRequestInfo requestInfo = helpers.analyzeRequest(rawRequest);

        String requestStr = new String(rawRequest);

        int bodyOffset = requestInfo.getBodyOffset();
        String bodySection = requestStr.substring(bodyOffset);

        List<String> headers = requestInfo.getHeaders();
        String requestLine = headers.get(0);

        String anonRequestLine = anonymizeRequestLine(requestLine);

        List<String> anonHeaders = new ArrayList<>();
        anonHeaders.add(anonRequestLine);
        for (int i = 1; i < headers.size(); i++) {
            anonHeaders.add(anonymizeHeader(headers.get(i)));
        }

        String anonBody = anonymizeBody(bodySection, requestInfo);

        StringBuilder result = new StringBuilder();
        for (String h : anonHeaders) {
            result.append(h).append("\r\n");
        }
        result.append("\r\n");
        result.append(anonBody);

        String finalResult = finalSweep(result.toString());
        return finalResult;
    }

    /**
     * Anonymize a full HTTP response (headers + body).
     */
    public String anonymizeResponse(byte[] rawResponse) {
        IResponseInfo responseInfo = helpers.analyzeResponse(rawResponse);
        String responseStr = new String(rawResponse);

        int bodyOffset = responseInfo.getBodyOffset();
        String bodySection = responseStr.substring(bodyOffset);

        List<String> headers = responseInfo.getHeaders();
        List<String> anonHeaders = new ArrayList<>();
        anonHeaders.add(headers.get(0));
        for (int i = 1; i < headers.size(); i++) {
            anonHeaders.add(anonymizeHeader(headers.get(i)));
        }

        String anonBody = anonymizeResponseBody(bodySection, responseInfo);

        StringBuilder result = new StringBuilder();
        for (String h : anonHeaders) {
            result.append(h).append("\r\n");
        }
        result.append("\r\n");
        result.append(anonBody);

        return finalSweep(result.toString());
    }

    // ==================== REQUEST LINE ====================

    private String anonymizeRequestLine(String requestLine) {
        String[] parts = requestLine.split(" ", 3);
        if (parts.length < 3) return requestLine;

        String method = parts[0];
        String pathAndQuery = parts[1];
        String httpVersion = parts[2];

        int qIdx = pathAndQuery.indexOf('?');
        String path = qIdx >= 0 ? pathAndQuery.substring(0, qIdx) : pathAndQuery;
        String query = qIdx >= 0 ? pathAndQuery.substring(qIdx + 1) : null;

        String anonQuery = null;
        if (query != null) {
            anonQuery = anonymizeQueryString(query);
        }

        StringBuilder sb = new StringBuilder();
        sb.append(method).append(" ").append(path);
        if (anonQuery != null) {
            sb.append("?").append(anonQuery);
        }
        sb.append(" ").append(httpVersion);
        return sb.toString();
    }

    private String anonymizeQueryString(String query) {
        String[] pairs = query.split("&");
        List<String> anonPairs = new ArrayList<>();
        for (String pair : pairs) {
            int eqIdx = pair.indexOf('=');
            if (eqIdx >= 0) {
                String name = pair.substring(0, eqIdx);
                String value = pair.substring(eqIdx + 1);
                String decodedValue = value;
                try { decodedValue = java.net.URLDecoder.decode(value, "UTF-8"); } catch (Exception e) {}
                String replacement = evaluateReplacement(name, decodedValue);
                if (replacement != null) {
                    anonPairs.add(name + "=" + replacement);
                } else {
                    anonPairs.add(pair);
                }
            } else {
                anonPairs.add(pair);
            }
        }
        return String.join("&", anonPairs);
    }

    // ==================== HEADERS ====================

    private String anonymizeHeader(String header) {
        int colonIdx = header.indexOf(':');
        if (colonIdx < 0) return header;

        String name = header.substring(0, colonIdx).trim();
        String value = header.substring(colonIdx + 1).trim();
        String nameLower = name.toLowerCase();

        // Host header
        if (nameLower.equals("host")) {
            return name + ": " + redactHost(value);
        }

        // Cookie header
        if (nameLower.equals("cookie")) {
            return name + ": " + anonymizeCookieHeader(value);
        }

        // Set-Cookie
        if (nameLower.equals("set-cookie") || nameLower.equals("set-cookie2")) {
            return name + ": " + anonymizeSetCookieHeader(value);
        }

        // Authorization / Proxy-Authorization
        if (nameLower.equals("authorization") || nameLower.equals("proxy-authorization")) {
            return name + ": " + anonymizeAuthValue(value);
        }

        // Origin / Referer
        if (nameLower.equals("origin") || nameLower.equals("referer")) {
            return name + ": " + anonymizeUrl(value);
        }

        // IP-carrying headers
        if (nameLower.equals("x-forwarded-for") || nameLower.startsWith("x-forwarded-for") ||
            nameLower.equals("x-real-ip") ||
            nameLower.equals("x-client-ip") || nameLower.equals("x-originating-ip") ||
            nameLower.equals("x-remote-ip") || nameLower.equals("x-remote-addr") ||
            nameLower.equals("true-client-ip") || nameLower.equals("cf-connecting-ip")) {
            return name + ": " + anonymizeIpList(value);
        }

        // Host-carrying headers
        if (nameLower.equals("x-forwarded-host") || nameLower.equals("x-forwarded-server")) {
            return name + ": " + redactHost(value);
        }

        // ETag headers, redact the hash value
        if (ETAG_HEADERS.contains(nameLower)) {
            return name + ": " + redactEtagValue(value);
        }

        // Oc-Fileid -- always redact (server-side file identifiers)
        if (nameLower.equals("oc-fileid")) {
            return name + ": REDACTED_FILE_ID";
        }

        // Requesttoken header (Nextcloud/Owncloud CSRF token)
        if (nameLower.equals("requesttoken")) {
            return name + ": " + redactNonceOrToken(value);
        }

        // Origin-Trial header (base64 blob containing origin info)
        if (nameLower.equals("origin-trial")) {
            return name + ": REDACTED_ORIGIN_TRIAL";
        }

        // DeviceId header (device fingerprint, often base64)
        if (nameLower.equals("deviceid") || nameLower.equals("x-deviceid") ||
            nameLower.equals("x-device-id") || nameLower.equals("x-device-fingerprint")) {
            return name + ": REDACTED_DEVICE_ID";
        }

        // X-Debug-Token
        if (nameLower.equals("x-debug-token") || nameLower.equals("x-debug-token-link")) {
            return name + ": REDACTED_DEBUG_TOKEN";
        }

        //  GPS/coordinate headers
        if (nameLower.equals("x-geo-location") || nameLower.equals("x-gps-coordinates") ||
            nameLower.equals("x-lat") || nameLower.equals("x-lng") ||
            nameLower.equals("x-latitude") || nameLower.equals("x-longitude")) {
            return name + ": REDACTED_COORDINATES";
        }

        // Known sensitive headers , redact the full value
        if (SENSITIVE_HEADERS.contains(nameLower)) {
            return name + ": " + redactTokenValue(name, value);
        }

        // Any X- header not already handled , redact if it looks like a secret
        if (nameLower.startsWith("x-") && !SENSITIVE_HEADERS.contains(nameLower)) {
            if (looksLikeSecret(value)) {
                return name + ": " + redactTokenValue(name, value);
            }
        }

        // Evaluate based on key and value
        String replacement = evaluateReplacement(name, value);
        if (replacement != null) {
            return name + ": " + replacement;
        }

        // Content-Type, Accept, Content-Length, etc.
        return header;
    }

    private String anonymizeCookieHeader(String cookieValue) {
        String[] cookies = cookieValue.split(";");
        List<String> anonCookies = new ArrayList<>();
        for (String cookie : cookies) {
            cookie = cookie.trim();
            int eqIdx = cookie.indexOf('=');
            if (eqIdx >= 0) {
                String cName = cookie.substring(0, eqIdx).trim();
                String cValue = cookie.substring(eqIdx + 1).trim();
                String replacement = evaluateReplacement(cName, cValue);
                if (replacement != null) {
                    anonCookies.add(redactCookieName(cName) + "=" + replacement);
                } else {
                    String anonName = redactCookieName(cName);
                    String anonValue = redactCookieValue(cValue);
                    anonCookies.add(anonName + "=" + anonValue);
                }
            } else {
                anonCookies.add(cookie);
            }
        }
        return String.join("; ", anonCookies);
    }

    private String anonymizeSetCookieHeader(String value) {
        String[] parts = value.split(";");
        if (parts.length > 0) {
            String mainCookie = parts[0].trim();
            int eqIdx = mainCookie.indexOf('=');
            if (eqIdx >= 0) {
                String cName = mainCookie.substring(0, eqIdx).trim();
                String cValue = mainCookie.substring(eqIdx + 1).trim();
                String replacement = evaluateReplacement(cName, cValue);
                if (replacement != null) {
                    parts[0] = redactCookieName(cName) + "=" + replacement;
                } else {
                    String anonName = redactCookieName(cName);
                    String anonValue = redactCookieValue(cValue);
                    parts[0] = anonName + "=" + anonValue;
                }
            }
        }
        List<String> anonParts = new ArrayList<>();
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i].trim();
            if (part.toLowerCase().startsWith("domain=")) {
                String domain = part.substring(7).trim();
                anonParts.add("Domain=" + redactHost(domain));
            } else {
                anonParts.add(i == 0 ? parts[0] : part);
            }
        }
        return String.join("; ", anonParts);
    }

    private String anonymizeAuthValue(String value) {
        Matcher bearerMatcher = BEARER_PATTERN.matcher(value);
        if (bearerMatcher.matches()) {
            return "Bearer REDACTED_BEARER_TOKEN";
        }

        Matcher basicMatcher = BASIC_PATTERN.matcher(value);
        if (basicMatcher.matches()) {
            return "Basic REDACTED_BASIC_CREDENTIALS";
        }

        Matcher digestMatcher = DIGEST_PATTERN.matcher(value);
        if (digestMatcher.matches()) {
            return "Digest REDACTED_DIGEST_CREDENTIALS";
        }

        Matcher ntlmMatcher = NTLM_PATTERN.matcher(value);
        if (ntlmMatcher.matches()) {
            return "NTLM REDACTED_NTLM_TOKEN";
        }

        Matcher negotiateMatcher = NEGOTIATE_PATTERN.matcher(value);
        if (negotiateMatcher.matches()) {
            return "Negotiate REDACTED_NEGOTIATE_TOKEN";
        }

        Matcher awsMatcher = AWS_SIGV4_PATTERN.matcher(value);
        if (awsMatcher.matches()) {
            return "AWS4-HMAC-SHA256 REDACTED_AWS_SIGNATURE";
        }

        return "REDACTED_AUTH_VALUE";
    }

    private String anonymizeUrl(String url) {
        try {
            Matcher m = DOMAIN_PATTERN.matcher(url);
            StringBuffer sb = new StringBuffer();
            while (m.find()) {
                String domain = m.group(1);
                String replacement = m.group(0).replace(domain, redactHost(domain));
                m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
            }
            m.appendTail(sb);
            return sb.toString();
        } catch (Exception e) {
            return "REDACTED_URL";
        }
    }

    private String anonymizeIpList(String value) {
        Matcher m = IPV4_PATTERN.matcher(value);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            m.appendReplacement(sb, Matcher.quoteReplacement(redactIp(m.group())));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    // ==================== BODY ANONYMIZATION ====================

    private String anonymizeBody(String body, IRequestInfo requestInfo) {
        if (body == null || body.trim().isEmpty()) return body;

        String contentType = getContentType(requestInfo.getHeaders());

        if (contentType != null) {
            if (contentType.contains("application/json")) {
                return anonymizeJsonBody(body);
            } else if (contentType.contains("application/x-www-form-urlencoded")) {
                return anonymizeFormBody(body);
            } else if (contentType.contains("multipart/form-data")) {
                return anonymizeMultipartBody(body);
            } else if (contentType.contains("application/xml") || contentType.contains("text/xml")) {
                return anonymizeXmlBody(body);
            } else if (contentType.contains("text/html")) {
                return anonymizeHtmlBody(body);
            }
        }

        // Fallback detection
        String trimmed = body.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            return anonymizeJsonBody(body);
        } else if (trimmed.contains("=") && trimmed.contains("&") && !trimmed.contains("<")) {
            return anonymizeFormBody(body);
        } else if (trimmed.startsWith("<!") || trimmed.startsWith("<html") || trimmed.startsWith("<head")) {
            return anonymizeHtmlBody(body);
        }

        return body; // Will be caught by finalSweep
    }

    private String anonymizeResponseBody(String body, IResponseInfo responseInfo) {
        if (body == null || body.trim().isEmpty()) return body;

        String contentType = getContentType(responseInfo.getHeaders());

        if (contentType != null) {
            if (contentType.contains("application/json")) {
                return anonymizeJsonBody(body);
            } else if (contentType.contains("application/xml") || contentType.contains("text/xml")) {
                return anonymizeXmlBody(body);
            } else if (contentType.contains("text/html")) {
                return anonymizeHtmlBody(body);
            }
        }

        String trimmed = body.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            return anonymizeJsonBody(body);
        } else if (trimmed.startsWith("<!") || trimmed.startsWith("<html") || trimmed.startsWith("<head")) {
            return anonymizeHtmlBody(body);
        }

        return body;
    }

    // ==================== SOFT CANDIDATES EVALUATION ====================

    private static final Set<String> PHONE_KEYS = new HashSet<>(Arrays.asList(
        "phone", "mobile", "tel", "telno", "cell", "cellphone", "mobileno", "phonenumber", "hotline", "fax", "faxnumber", "extension", "ext", "emplphone", "userphone", "contactphone", "mobilephone", "mobilenumber"
    ));

    private static final Set<String> ADDRESS_KEYS = new HashSet<>(Arrays.asList(
        "addr", "street", "address", "adres", "addrress", "addrres", "addressline", "place", "location", "residence", "domicile", "housenumber", "hnumber", "homenumber", "flatnumber", "aptnumber", "number", "address1", "addr1", "premises", "building"
    ));

    private String evaluateStricterCandidate(String value) {
        if (value == null || value.isEmpty()) return null;
        if (EMAIL_PATTERN.matcher(value).find()) return redactEmail(value);
        
        Matcher mPan = PAN_PATTERN.matcher(value);
        if (mPan.find()) {
            String digits = mPan.group().replaceAll("[\\s\\-]", "");
            if (digits.length() >= 13 && digits.length() <= 19 && luhnCheck(digits)) return redactPan(mPan.group());
        }
        
        Matcher mIbanC = IBAN_COMPACT_PATTERN.matcher(value);
        if (mIbanC.find()) {
            String compact = mIbanC.group().toUpperCase();
            if (compact.length() >= 12 && isValidIbanStructure(compact)) return redactIban(mIbanC.group());
        }
        Matcher mIban = IBAN_PATTERN.matcher(value);
        if (mIban.find()) {
            String compact = mIban.group().replaceAll("\\s", "").toUpperCase();
            if (compact.length() >= 12 && isValidIbanStructure(compact)) return redactIban(mIban.group());
        }

        Matcher mSsn = SSN_PATTERN.matcher(value);
        if (mSsn.find()) return redactSsn(mSsn.group());

        Matcher mSin = SIN_PATTERN.matcher(value);
        if (mSin.find()) {
            String digits = mSin.group().replaceAll("[\\s\\-]", "");
            if (digits.length() == 9 && luhnCheck(digits)) return redactGovId(mSin.group(), "SIN");
        }

        Matcher mNin = NIN_PATTERN.matcher(value);
        if (mNin.find()) return redactGovId(mNin.group(), "NIN");

        Matcher mEmirates = EMIRATES_ID_PATTERN.matcher(value);
        if (mEmirates.find()) return redactGovId(mEmirates.group(), "EMIRATES_ID");

        Matcher mAadhaar = AADHAAR_PATTERN.matcher(value);
        if (mAadhaar.find()) {
            String digits = mAadhaar.group().replaceAll("\\s", "");
            if (digits.length() == 12) return redactGovId(mAadhaar.group(), "AADHAAR");
        }

        return null;
    }

    private String evaluateSoftCandidate(String key, String value) {
        if (key == null || value == null || value.isEmpty() || value.length() > 500) return null;

        String fuzzyKey = key.toLowerCase().replaceAll("[^a-z0-9]", "");

        boolean phoneKeyMatch = false;
        for (String pk : PHONE_KEYS) {
            if (fuzzyKey.contains(pk)) {
                phoneKeyMatch = true; break;
            }
        }

        if (phoneKeyMatch) {
            String normPhone = value.replaceAll("[\\s\\-\\.\\(\\)]", "");
            if (normPhone.matches("^[+]?[0-9]{4,16}$")) {
                return redactPhone(value);
            }
        }

        boolean addressKeyMatch = false;
        for (String ak : ADDRESS_KEYS) {
            if (fuzzyKey.contains(ak)) {
                addressKeyMatch = true; break;
            }
        }

        if (addressKeyMatch) {
            int numDigits = 0;
            int numLetters = 0;
            int numSpaces = 0;
            for (char c : value.toCharArray()) {
                if (Character.isDigit(c)) numDigits++;
                else if (Character.isLetter(c)) numLetters++;
                else if (Character.isWhitespace(c)) numSpaces++;
            }
            if (numDigits >= 1 && numSpaces >= 1 && numLetters >= 3) {
                return redactAddress(value);
            }
        }

        return null;
    }

    private String evaluateReplacement(String key, String value) {
        if (key == null || value == null || value.isEmpty()) return null;

        if (FULL_REDACT_KEYS.contains(key.toLowerCase())) {
            return "REDACTED_" + key.toUpperCase();
        }

        String strictRedacted = evaluateStricterCandidate(value);
        String softRedacted = evaluateSoftCandidate(key, value);

        if (strictRedacted != null && isSensitiveParam(key)) {
            return strictRedacted;
        }

        if (softRedacted != null) {
            return softRedacted;
        }

        if (isSensitiveParam(key)) {
            return strictRedacted != null ? strictRedacted : "REDACTED_VALUE";
        }

        return null;
    }

    private String redactAddress(String address) {
        if (!addressMap.containsKey(address)) {
            addressMap.put(address, "REDACTED_ADDRESS_" + addressCounter);
            addressCounter++;
        }
        return addressMap.get(address);
    }

    private String redactGenericId(String id) {
        if (!genericIdMap.containsKey(id)) {
            genericIdMap.put(id, "REDACTED_ID_" + genericIdCounter);
            genericIdCounter++;
        }
        return genericIdMap.get(id);
    }

    private String redactNumericId(String id) {
        if (!numericIdMap.containsKey(id)) {
            numericIdMap.put(id, "REDACTED_NUMERIC_ID_" + numericIdCounter);
            numericIdCounter++;
        }
        return numericIdMap.get(id);
    }

    private String redactPassport(String id) {
        if (!paspMap.containsKey(id)) {
            paspMap.put(id, "REDACTED_PASSPORT_" + paspCounter);
            paspCounter++;
        }
        return paspMap.get(id);
    }

    private String redactNricSg(String id) {
        if (!nricSgMap.containsKey(id)) {
            nricSgMap.put(id, "REDACTED_NRIC_" + nricSgCounter);
            nricSgCounter++;
        }
        return nricSgMap.get(id);
    }

    private String redactTfnAu(String id) {
        if (!tfnAuMap.containsKey(id)) {
            tfnAuMap.put(id, "REDACTED_TFN_" + tfnAuCounter);
            tfnAuCounter++;
        }
        return tfnAuMap.get(id);
    }

    private String redactAhvCh(String id) {
        if (!ahvChMap.containsKey(id)) {
            ahvChMap.put(id, "REDACTED_AHV_" + ahvChCounter);
            ahvChCounter++;
        }
        return ahvChMap.get(id);
    }

    private String redactPeselPl(String id) {
        if (!peselPlMap.containsKey(id)) {
            peselPlMap.put(id, "REDACTED_PESEL_" + peselPlCounter);
            peselPlCounter++;
        }
        return peselPlMap.get(id);
    }

    /**
     * JSON body: redact values of sensitive keys.
     */
    private String anonymizeJsonBody(String body) {
        Pattern jsonKeyValue = Pattern.compile(
            "\"([^\"]+)\"\\s*:\\s*(\"([^\"]*)\"|(-?\\d+\\.?\\d*)|true|false|null)",
            Pattern.CASE_INSENSITIVE
        );

        Matcher m = jsonKeyValue.matcher(body);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String key = m.group(1);
            String fullValue = m.group(2);

            String replacement = evaluateReplacement(key, fullValue);
            if (replacement != null) {
                m.appendReplacement(sb, Matcher.quoteReplacement(
                    "\"" + key + "\": \"" + replacement + "\""));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(m.group()));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Form-encoded body: password=s3cr3t&username=admin
     */
    private String anonymizeFormBody(String body) {
        String[] pairs = body.split("&");
        List<String> anonPairs = new ArrayList<>();
        for (String pair : pairs) {
            int eqIdx = pair.indexOf('=');
            if (eqIdx >= 0) {
                String name = pair.substring(0, eqIdx);
                String value = pair.substring(eqIdx + 1);
                String replacement = evaluateReplacement(name, value);
                if (replacement != null) {
                    anonPairs.add(name + "=" + replacement);
                } else {
                    anonPairs.add(pair);
                }
            } else {
                anonPairs.add(pair);
            }
        }
        return String.join("&", anonPairs);
    }

    /**
     * Multipart body: find sensitive field names and redact their values.
     */
    private String anonymizeMultipartBody(String body) {
        Pattern multipartField = Pattern.compile(
            "(Content-Disposition:\\s*form-data;\\s*name=\"([^\"]+)\"(?:;\\s*filename=\"([^\"]+)\")?[^\\r\\n]*(?:\\r?\\n[a-zA-Z0-9\\-]+:\\s*[^\\r\\n]*)*\\r?\\n\\r?\\n)(.*?)(?=\\r?\\n--|$)",
            Pattern.DOTALL
        );

        Matcher m = multipartField.matcher(body);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String fieldName = m.group(2);
            String value = m.group(4);
            String headerPart = m.group(1);
            if (headerPart.contains("filename=\"")) {
                headerPart = headerPart.replaceAll("filename=\"[^\"]+\"", "filename=\"REDACTED_FILENAME.ext\"");
            }
            String replacement = evaluateReplacement(fieldName, value);
            if (replacement != null) {
                m.appendReplacement(sb, Matcher.quoteReplacement(headerPart + replacement));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(headerPart + value));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * XML body: redact content of sensitive element names.
     */
    private String anonymizeXmlBody(String body) {
        Pattern anyTagPattern = Pattern.compile(
            "(<([^/?! \\t\\n\\r>]+)[^>]*>)(.*?)(</\\2>)",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL
        );
        Matcher m = anyTagPattern.matcher(body);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String tagName = m.group(2);
            String value = m.group(3);
            if (!value.contains("<")) { 
                String replacement = evaluateReplacement(tagName, value);
                if (replacement != null) {
                    m.appendReplacement(sb, Matcher.quoteReplacement(m.group(1) + replacement + m.group(4)));
                    continue; // Skip next check for this tag
                }
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(m.group(0)));
        }
        m.appendTail(sb);
        body = sb.toString();

        for (String param : SENSITIVE_PARAMS) {
            Pattern xmlPattern = Pattern.compile(
                "(<" + Pattern.quote(param) + "(?:\\s[^>]*)?>)(.*?)(</" + Pattern.quote(param) + ">)",
                Pattern.CASE_INSENSITIVE | Pattern.DOTALL
            );
            body = xmlPattern.matcher(body).replaceAll("$1REDACTED_VALUE$3");
        }
        return body;
    }

    /**
     * HTML body: redact sensitive data attributes, nonces, inline scripts,
     * usernames, display names, request tokens, title content, etc.
     */
    private String anonymizeHtmlBody(String body) {
        // 1. data-user="username"
        body = replaceAllGrouped(body, DATA_USER_ATTR, m -> {
            return m.group(1) + redactUsername(m.group(2)) + m.group(3);
        });

        // 2. data-user-displayname="Full Name"
        body = replaceAllGrouped(body, DATA_DISPLAYNAME_ATTR, m -> {
            return m.group(1) + "REDACTED_DISPLAY_NAME" + m.group(3);
        });

        // 3. data-requesttoken="token"
        body = replaceAllGrouped(body, DATA_REQUESTTOKEN_ATTR, m -> {
            return m.group(1) + redactNonceOrToken(m.group(2)) + m.group(3);
        });

        // 4. nonce="value" attributes (CSP nonces)
        body = replaceAllGrouped(body, NONCE_ATTR, m -> {
            return m.group(1) + redactNonce(m.group(2)) + m.group(3);
        });

        // 5. data:text/javascript;base64,ENCODED
        body = replaceAllGrouped(body, DATA_URI_BASE64, m -> {
            return m.group(1) + "REDACTED_BASE64_DATA";
        });

        // 6. data-btmanifest="identifier"
        body = replaceAllGrouped(body, DATA_BTMANIFEST_ATTR, m -> {
            return m.group(1) + "REDACTED_MANIFEST_ID" + m.group(3);
        });

        // 7. Generic data-*token*, data-*session*, data-*key* attributes
        body = replaceAllGrouped(body, DATA_SENSITIVE_ATTR, m -> {
            return m.group(1) + "REDACTED_DATA_ATTR" + m.group(3);
        });

        // 8. <title>Content - AppName</title> -- redact app/service names
        body = replaceAllGrouped(body, HTML_TITLE_PATTERN, m -> {
            return m.group(1) + "REDACTED_PAGE_TITLE" + m.group(3);
        });

        // 9. Also apply JSON redaction if there's inline JSON in the HTML
        // (script blocks often contain JSON config with tokens)

        return body;
    }

    // ==================== FINAL SWEEP ====================

    /**
     * Final pass over the entire output to catch patterns anywhere:
     *  - JWTs, UUIDs, IPs, emails, AWS keys
     *  - Base64 tokens (nonces, request tokens, device IDs)
     *  - Hex tokens (etags, file IDs, debug tokens)
     *  - Remaining hostnames
     *  - Long base64 blobs
     *  - data: URI base64 content
     *  - nonce attributes
     *  - data-user attributes
     *  - PAN/credit cards (Luhn), IBAN, SWIFT/BIC, SSN, SIN, NIN
     *  - EU ID, Emirates ID, Turkish TC, Saudi ID, Qatar ID, Aadhaar
     *  - Phone numbers (E.164 + formatted)
     *  - GPS coordinates
     */
    private String finalSweep(String text) {
        // 1. Replace JWTs
        text = replaceAllGrouped(text, JWT_PATTERN, m -> redactJwt(m.group()));

        // 2. Replace UUIDs
        text = replaceAllGrouped(text, UUID_PATTERN, m -> redactUuid(m.group()));

        // 3. Replace AWS keys
        text = replaceAllGrouped(text, AWS_KEY_PATTERN, m -> "REDACTED_AWS_KEY");

        // 4. Replace emails
        text = replaceAllGrouped(text, EMAIL_PATTERN, m -> redactEmail(m.group()));

        // 5. Replace IPs
        text = replaceIps(text);

        // 6. Replace data-user attributes (in case they appear in non-HTML context)
        text = replaceAllGrouped(text, DATA_USER_ATTR, m ->
            m.group(1) + redactUsername(m.group(2)) + m.group(3));

        // 7. Replace data-user-displayname attributes
        text = replaceAllGrouped(text, DATA_DISPLAYNAME_ATTR, m ->
            m.group(1) + "REDACTED_DISPLAY_NAME" + m.group(3));

        // 8. Replace data-requesttoken attributes
        text = replaceAllGrouped(text, DATA_REQUESTTOKEN_ATTR, m ->
            m.group(1) + redactNonceOrToken(m.group(2)) + m.group(3));

        // 9. Replace nonce attributes
        text = replaceAllGrouped(text, NONCE_ATTR, m ->
            m.group(1) + redactNonce(m.group(2)) + m.group(3));

        // 10. Replace data: URI base64 content
        text = replaceAllGrouped(text, DATA_URI_BASE64, m ->
            m.group(1) + "REDACTED_BASE64_DATA");

        // 11. Replace data-btmanifest
        text = replaceAllGrouped(text, DATA_BTMANIFEST_ATTR, m ->
            m.group(1) + "REDACTED_MANIFEST_ID" + m.group(3));

        // 12. Replace generic data-*sensitive* attributes
        text = replaceAllGrouped(text, DATA_SENSITIVE_ATTR, m ->
            m.group(1) + "REDACTED_DATA_ATTR" + m.group(3));

        // 13. Replace <title> content
        text = replaceAllGrouped(text, HTML_TITLE_PATTERN, m ->
            m.group(1) + "REDACTED_PAGE_TITLE" + m.group(3));

        // ==================== VALUE-BASED DETECTIONS ====================
        // These run regardless of key/field name, catching sensitive data anywhere.

        // 14. PAN / Credit card numbers (with Luhn validation)
        text = replacePanNumbers(text);

        // 15. IBAN numbers
        text = replaceIbanNumbers(text);

        // 16. SWIFT/BIC codes
        text = replaceSwiftBic(text);

        // 17. US SSN (XXX-XX-XXXX)
        text = replaceSsn(text);

        // 18. Canada SIN (XXX-XXX-XXX)
        text = replaceSin(text);

        // 19. UK NIN (AB 12 34 56 C)
        text = replaceNin(text);

        // 20. UAE Emirates ID (784-YYYY-NNNNNNN-C)
        text = replaceEmiratesId(text);

        // 21. India Aadhaar (XXXX XXXX XXXX)
        text = replaceAadhaar(text);

        // 22. Phone numbers (E.164 + international + US/CA format)
        text = replacePhoneNumbers(text);

        // 23. GPS coordinates (decimal pairs with 4+ decimal places)
        text = replaceCoordinates(text);

        // 23.5. Generic sweeps
        text = replaceGenericAddresses(text);
        text = replaceGenericIds(text);
        text = replaceNumericIds(text);

        // 23.6 NEW STRICT AND GENERIC ALPHANUMERIC SWEEPS
        // IMPORTANT: UAE/structured IDs must run BEFORE generic alphanum to avoid partial-match collision
        text = replaceKimlik(text);
        text = replaceSaudiId(text);
        text = replaceQatarId(text);
        text = replacePassports(text);
        text = replaceNricSg(text);
        text = replaceTfnAu(text);
        text = replaceAhvCh(text);
        text = replacePeselPl(text);
        text = replaceGenericPatterns(text); 
        text = replaceAlphanumId(text);

        // ==================== EXISTING SWEEP (order preserved) ====================

        // 24. Replace long base64 strings (tokens like Requesttoken values,
        //     Origin-Trial blobs, DeviceId fingerprints)
        //     Must run AFTER JWT replacement to avoid double-processing
        text = replaceLongBase64(text);

        // 25. Replace hex tokens (etag values, file IDs, debug tokens)
        text = replaceHexTokens(text);

        // 26. Replace any remaining original hostname occurrences
        if (originalHost != null && !originalHost.isEmpty()) {
            text = text.replace(originalHost, getHostMapping(originalHost));
            text = replaceIgnoreCase(text, originalHost, getHostMapping(originalHost));
        }

        // 27. Replace remaining domains
        text = replaceDomains(text);

        return text;
    }

    // ==================== VALUE-BASED REPLACEMENT METHODS ====================

    /**
     * Detect and redact PAN/credit card numbers using Luhn algorithm validation.
     * Catches numbers regardless of key name - purely value-based.
     */
    private String replacePanNumbers(String text) {
        Matcher m = PAN_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String fullMatch = m.group();
            // Extract only digits for Luhn check
            String digits = fullMatch.replaceAll("[\\s\\-]", "");
            // Must be 13-19 digits and pass Luhn
            if (digits.length() >= 13 && digits.length() <= 19 && luhnCheck(digits)) {
                // Skip if it's already redacted
                if (fullMatch.startsWith("REDACTED_")) {
                    m.appendReplacement(sb, Matcher.quoteReplacement(fullMatch));
                } else {
                    m.appendReplacement(sb, Matcher.quoteReplacement(redactPan(fullMatch)));
                }
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(fullMatch));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Luhn algorithm (mod 10) for credit card validation.
     * Returns true if the digit string passes the Luhn check.
     */
    public static boolean luhnCheck(String digits) {
        if (digits == null || digits.isEmpty()) return false;
        int sum = 0;
        boolean alternate = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            char c = digits.charAt(i);
            if (c < '0' || c > '9') return false;
            int n = c - '0';
            if (alternate) {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        return sum % 10 == 0;
    }

    /**
     * Detect and redact IBAN numbers (value-based).
     */
    private String replaceIbanNumbers(String text) {
        // First pass: compact IBANs (no spaces)
        Matcher m = IBAN_COMPACT_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            if (match.startsWith("REDACTED_")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
            } else if (isValidIbanStructure(match.replaceAll("\\s", "").toUpperCase())) {
                m.appendReplacement(sb, Matcher.quoteReplacement(redactIban(match)));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
            }
        }
        m.appendTail(sb);
        text = sb.toString();

        // Second pass: IBANs with spaces (using the spaced pattern)
        m = IBAN_PATTERN.matcher(text);
        sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            String compact = match.replaceAll("\\s", "").toUpperCase();
            if (match.contains("REDACTED_")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
            } else if (compact.length() >= 12 && isValidIbanStructure(compact)) {
                m.appendReplacement(sb, Matcher.quoteReplacement(redactIban(match)));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Validates basic IBAN structure: correct length per country and mod-97 check.
     */
    public static boolean isValidIbanStructure(String iban) {
        if (iban == null || iban.length() < 12 || iban.length() > 34) return false;
        iban = iban.toUpperCase().replaceAll("\\s", "");

        // Check first two chars are letters, next two are digits
        if (!Character.isLetter(iban.charAt(0)) || !Character.isLetter(iban.charAt(1))) return false;
        if (!Character.isDigit(iban.charAt(2)) || !Character.isDigit(iban.charAt(3))) return false;

        // IBAN country lengths (common ones)
        Map<String, Integer> lengths = new HashMap<>();
        lengths.put("AL", 28); lengths.put("AD", 24); lengths.put("AT", 20);
        lengths.put("AZ", 28); lengths.put("BH", 22); lengths.put("BY", 28);
        lengths.put("BE", 16); lengths.put("BA", 20); lengths.put("BR", 29);
        lengths.put("BG", 22); lengths.put("CR", 22); lengths.put("HR", 21);
        lengths.put("CY", 28); lengths.put("CZ", 24); lengths.put("DK", 18);
        lengths.put("DO", 28); lengths.put("TL", 23); lengths.put("EE", 20);
        lengths.put("FO", 18); lengths.put("FI", 18); lengths.put("FR", 27);
        lengths.put("GE", 22); lengths.put("DE", 22); lengths.put("GI", 23);
        lengths.put("GR", 27); lengths.put("GL", 18); lengths.put("GT", 28);
        lengths.put("HU", 28); lengths.put("IS", 26); lengths.put("IQ", 23);
        lengths.put("IE", 22); lengths.put("IL", 23); lengths.put("IT", 27);
        lengths.put("JO", 30); lengths.put("KZ", 20); lengths.put("XK", 20);
        lengths.put("KW", 30); lengths.put("LV", 21); lengths.put("LB", 28);
        lengths.put("LI", 21); lengths.put("LT", 20); lengths.put("LU", 20);
        lengths.put("MK", 19); lengths.put("MT", 31); lengths.put("MR", 27);
        lengths.put("MU", 30); lengths.put("MC", 27); lengths.put("MD", 24);
        lengths.put("ME", 22); lengths.put("NL", 18); lengths.put("NO", 15);
        lengths.put("PK", 24); lengths.put("PS", 29); lengths.put("PL", 28);
        lengths.put("PT", 25); lengths.put("QA", 29); lengths.put("RO", 24);
        lengths.put("LC", 32); lengths.put("SM", 27); lengths.put("ST", 25);
        lengths.put("SA", 24); lengths.put("RS", 22); lengths.put("SC", 31);
        lengths.put("SK", 24); lengths.put("SI", 19); lengths.put("ES", 24);
        lengths.put("SE", 24); lengths.put("CH", 21); lengths.put("TN", 24);
        lengths.put("TR", 26); lengths.put("UA", 29); lengths.put("AE", 23);
        lengths.put("GB", 22); lengths.put("VA", 22); lengths.put("VG", 24);

        String country = iban.substring(0, 2);
        Integer expectedLength = lengths.get(country);
        if (expectedLength != null && iban.length() != expectedLength) return false;

        // Mod 97 check: move first 4 chars to end, convert letters to numbers, check mod 97 == 1
        try {
            String rearranged = iban.substring(4) + iban.substring(0, 4);
            StringBuilder numericIban = new StringBuilder();
            for (char c : rearranged.toCharArray()) {
                if (Character.isDigit(c)) {
                    numericIban.append(c);
                } else if (Character.isLetter(c)) {
                    numericIban.append(Character.toUpperCase(c) - 'A' + 10);
                } else {
                    return false;
                }
            }
            // Use modular arithmetic to handle large numbers
            int remainder = 0;
            for (int i = 0; i < numericIban.length(); i++) {
                remainder = (remainder * 10 + (numericIban.charAt(i) - '0')) % 97;
            }
            return remainder == 1;
        } catch (Exception e) {
            return false;
        }
    }

    private String replaceSwiftBic(String text) {
        // Pattern for SWIFT/: 4 letters (bank) + 2 letters (country) + 2 alnum (location) + optional 3 alnum (branch)
        Matcher m = SWIFT_BIC_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            int start = m.start();
            // Check context: is this near a banking-related key or in a value context?
            int contextStart = Math.max(0, start - 300);
            String before = text.substring(contextStart, start).toLowerCase();
            if (before.contains("swift") || before.contains("bic") || before.contains("bank") ||
                before.contains("iban") || before.contains("routing") || before.contains("sort_code") ||
                before.contains("correspondent") || before.contains("beneficiary") ||
                // Also match if preceded by JSON/form value indicators
                before.endsWith("\":\"") || before.endsWith("\": \"") ||
                before.endsWith("=")) {
                m.appendReplacement(sb, Matcher.quoteReplacement("REDACTED_SWIFT_BIC"));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Detect and redact US Social Security Numbers (XXX-XX-XXXX).
     */
    private String replaceSsn(String text) {
        Matcher m = SSN_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            if (match.startsWith("REDACTED_")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(redactSsn(match)));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Detect and redact Canada SIN (XXX-XXX-XXX or XXX XXX XXX).
     */
    private String replaceSin(String text) {
        Matcher m = SIN_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String fullMatch = m.group();
            String digits = fullMatch.replaceAll("[\\s\\-\\u2011\\u2012\\u2013\\u2014]", "");
            if (digits.length() == 9 && luhnCheck(digits)) {
                if (fullMatch.startsWith("REDACTED_")) {
                    m.appendReplacement(sb, Matcher.quoteReplacement(fullMatch));
                } else {
                    m.appendReplacement(sb, Matcher.quoteReplacement(redactGovId(fullMatch, "SIN")));
                }
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(fullMatch));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Detect and redact UK National Insurance Numbers.
     */
    private String replaceNin(String text) {
        Matcher m = NIN_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            if (match.startsWith("REDACTED_")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(redactGovId(match, "NIN")));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Detect and redact UAE Emirates IDs (784-YYYY-NNNNNNN-C).
     */
    private String replaceEmiratesId(String text) {
        Matcher m = EMIRATES_ID_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            if (match.startsWith("REDACTED_")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(redactGovId(match, "EMIRATES_ID")));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Detect and redact India Aadhaar numbers (12 digits, starting with 2-9).
     */
    private String replaceAadhaar(String text) {
        Matcher m = AADHAAR_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            String digits = match.replaceAll("\\s", "");
            if (digits.length() == 12) {
                if (match.startsWith("REDACTED_")) {
                    m.appendReplacement(sb, Matcher.quoteReplacement(match));
                } else {
                    m.appendReplacement(sb, Matcher.quoteReplacement(redactGovId(match, "AADHAAR")));
                }
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Detect and redact phone numbers in various formats.
     */
    private String replacePhoneNumbers(String text) {
        // E.164 format (strictest, do first): +1234567890
        text = replaceAllGrouped(text, PHONE_E164_PATTERN, m -> {
            String match = m.group();
            if (match.startsWith("REDACTED_")) return match;
            return redactPhone(match);
        });

        // International with separators: +1-234-567-8901
        text = replaceAllGrouped(text, PHONE_INTL_PATTERN, m -> {
            String match = m.group();
            if (match.startsWith("REDACTED_") || match.contains("REDACTED_")) return match;
            return redactPhone(match);
        });

        // US/CA format: (123) 456-7890 - only in clear value context to avoid false positives
        Matcher m = PHONE_US_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            int start = m.start();
            if (match.contains("REDACTED_")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
                continue;
            }
            // Check context for phone-related hints
            int contextStart = Math.max(0, start - 300);
            String before = text.substring(contextStart, start).toLowerCase();
            if (before.contains("phone") || before.contains("mobile") || before.contains("cell") ||
                before.contains("tel") || before.contains("fax") || before.contains("sms") ||
                before.contains("msisdn") || before.contains("calling") ||
                before.endsWith("\":\"") || before.endsWith("\": \"") ||
                before.endsWith("=") || before.contains("contact")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(redactPhone(match)));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Detect and redact GPS/decimal coordinates.
     */
    private String replaceCoordinates(String text) {
        // Decimal coordinate pairs (lat, lon with 4+ decimal places)
        text = replaceAllGrouped(text, COORD_DECIMAL_PATTERN, m -> {
            String match = m.group();
            if (match.contains("REDACTED_")) return match;
            return redactCoord(match);
        });

        // Single high-precision decimal values near coordinate-related keys
        Matcher m = COORD_SINGLE_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            int start = m.start();
            if (match.contains("REDACTED_")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
                continue;
            }
            int contextStart = Math.max(0, start - 300);
            String before = text.substring(contextStart, start).toLowerCase();
            if (before.contains("lat") || before.contains("lng") || before.contains("lon") ||
                before.contains("coord") || before.contains("gps") || before.contains("geo") ||
                before.contains("location") || before.contains("position")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(redactCoord(match)));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private String replaceGenericAddresses(String text) {
        text = replaceAllGrouped(text, GENERIC_ADDRESS_PATTERN, m -> {
            String match = m.group();
            if (match.startsWith("REDACTED_")) return match;
            return redactAddress(match);
        });

        text = replaceAllGrouped(text, UK_POSTCODE_PATTERN, m -> {
            String match = m.group();
            if (match.startsWith("REDACTED_")) return match;
            return redactAddress(match);
        });

        return text;
    }

    private String replaceGenericIds(String text) {
        return replaceAllGrouped(text, GENERIC_ID_PATTERN, m -> {
            String match = m.group();
            if (match.startsWith("REDACTED_")) return match;
            return redactGenericId(match);
        });
    }

    private String replaceNumericIds(String text) {
        Matcher m = LOOSE_PHONE_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            int start = m.start();
            if (match.contains("REDACTED_") || match.startsWith("00000000")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
                continue;
            }
            int contextStart = Math.max(0, start - 300);
            String before = text.substring(contextStart, start).toLowerCase();
            if (before.contains("phone") || before.contains("mobile") || before.contains("cell") ||
                before.contains("tel") || before.contains("fax") || before.contains("sms") ||
                before.contains("msisdn") || before.contains("call") || before.contains("contact") ||
                before.contains("landline") || before.contains("ext")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(redactPhone(match)));
            } else if (before.contains("tracking") || before.contains("ship") || before.contains("order")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(redactNumericId(match)));
            } else if (before.contains("tax") || before.contains("ssn") || before.contains("nino") ||
                       before.contains("ahv") || before.contains("health") || before.contains("nric") ||
                       before.contains("tfn") || before.contains("pesel")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(redactGovId(match, "ID")));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(redactNumericId(match)));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private String replacePeselPl(String text) {
        Matcher m = PESEL_PL_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            int start = m.start();
            if (match.startsWith("REDACTED_")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
                continue;
            }
            int contextStart = Math.max(0, start - 300);
            String before = text.substring(contextStart, start).toLowerCase();
            if (before.contains("pesel") || before.contains("poland") || before.contains("id") || before.contains("national_id")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(redactPeselPl(match)));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private String replaceAhvCh(String text) {
        Matcher m = AHV_CH_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            if (match.startsWith("REDACTED_")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(redactAhvCh(match)));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private String replaceTfnAu(String text) {
        Matcher m = TFN_AU_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            int start = m.start();
            if (match.startsWith("REDACTED_")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
                continue;
            }
            int contextStart = Math.max(0, start - 300);
            String before = text.substring(contextStart, start).toLowerCase();
            if (before.contains("tfn") || before.contains("tax") || before.contains("australia")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(redactTfnAu(match)));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private String replaceNricSg(String text) {
        Matcher m = NRIC_SG_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            if (match.startsWith("REDACTED_")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(redactNricSg(match)));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private String replaceKimlik(String text) {
        Matcher m = TC_KIMLIK_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            if (m.group().startsWith("REDACTED_")) m.appendReplacement(sb, Matcher.quoteReplacement(m.group()));
            else m.appendReplacement(sb, Matcher.quoteReplacement(redactGovId(m.group(), "KIMLIK")));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private String replaceSaudiId(String text) {
        Matcher m = SAUDI_ID_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            if (m.group().startsWith("REDACTED_")) m.appendReplacement(sb, Matcher.quoteReplacement(m.group()));
            else m.appendReplacement(sb, Matcher.quoteReplacement(redactGovId(m.group(), "SAUDI_ID")));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private String replaceQatarId(String text) {
        Matcher m = QATAR_ID_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            if (m.group().startsWith("REDACTED_")) m.appendReplacement(sb, Matcher.quoteReplacement(m.group()));
            else m.appendReplacement(sb, Matcher.quoteReplacement(redactGovId(m.group(), "QATAR_ID")));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Passports: 0-2 letters + 7-9 digits.
     */
    private String replacePassports(String text) {
        Matcher m = PASSPORT_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            if (match.startsWith("REDACTED_")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
                continue;
            }
            int start = m.start();
            int contextStart = Math.max(0, start - 300);
            String before = text.substring(contextStart, start).toLowerCase();

            if (before.contains("passport") || before.contains("pass") || before.contains("pasp") || before.contains("paxpot") || before.contains("travel")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(redactPassport(match)));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Generic Alphanumeric IDs: 1-2 letters + 6-10 digits.
     */
    private String replaceAlphanumId(String text) {
        Matcher m = ALPHANUM_ID_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            if (match.startsWith("REDACTED_")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
            } else {
                // Completely unconditional since alphanumeric structure is strong
                m.appendReplacement(sb, Matcher.quoteReplacement(redactGenericId(match)));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private String replaceGenericPatterns(String text) {
        text = replaceAllGrouped(text, LOCAL_PHONE_PATTERN, m -> {
            String match = m.group();
            if (match.contains("REDACTED_")) return match;
            return redactGenericId(match);
        });
        text = replaceAllGrouped(text, PREFIX_6_ALPHANUM_PATTERN, m -> {
            String match = m.group();
            if (match.contains("REDACTED_")) return match;
            return redactGenericId(match);
        });
        text = replaceAllGrouped(text, GROUPED_11_PATTERN, m -> {
            String match = m.group();
            if (match.contains("REDACTED_")) return match;
            return redactGenericId(match);
        });
        text = replaceAllGrouped(text, RELAXED_UAE_ID_PATTERN, m -> {
            String match = m.group();
            if (match.contains("REDACTED_")) return match;
            return redactGovId(match, "EMIRATES_ID");
        });
        return text;
    }

    // ==================== EXISTING SWEEP HELPERS ====================

    private String replaceIps(String text) {
        Matcher m = IPV4_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String ip = m.group();
            if (ip.equals("127.0.0.1") || ip.equals("0.0.0.0")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(ip));
            } else {
                m.appendReplacement(sb, Matcher.quoteReplacement(redactIp(ip)));
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Replace long base64 strings that likely contain sensitive data.
     * Skips already-redacted placeholders and common safe patterns.
     */
    private String replaceLongBase64(String text) {
        Matcher m = LONG_BASE64_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            // Skip if it's already a REDACTED_ placeholder
            if (match.startsWith("REDACTED_")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
                continue;
            }
            // Skip if it looks like a URL path
            if (match.contains("/")) {
                String[] segments = match.split("/");
                int realSegments = 0;
                boolean hasLongSegment = false;
                for (String seg : segments) {
                    if (seg.isEmpty()) continue;
                    realSegments++;
                    if (seg.length() >= 12) {
                        hasLongSegment = true;
                    }
                }
                if (realSegments >= 2 && !hasLongSegment) {
                    m.appendReplacement(sb, Matcher.quoteReplacement(match));
                    continue;
                }
            }
            // Skip if it's only letters (normal word, not a token)
            if (match.matches("[a-zA-Z]+")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
                continue;
            }
            // Must contain at least some non-alpha chars
            boolean hasBase64Chars = false;
            for (char c : match.toCharArray()) {
                if (Character.isDigit(c) || c == '+' || c == '=') {
                    hasBase64Chars = true;
                    break;
                }
            }
            if (!hasBase64Chars) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
                continue;
            }
           
            m.appendReplacement(sb, Matcher.quoteReplacement(redactBase64Token(match)));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Replace hex tokens (24+ hex chars) that are likely etags, file IDs, debug tokens.
     */
    private String replaceHexTokens(String text) {
        Matcher m = HEX_TOKEN_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String match = m.group();
            if (match.startsWith("REDACTED_") || match.startsWith("00000000")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(match));
                continue;
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(redactHexToken(match)));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    // File extensions that should NOT be treated as TLDs in domain detection
    private static final Set<String> FILE_EXTENSIONS = new HashSet<>(Arrays.asList(
        "php", "asp", "aspx", "jsp", "jspx", "cgi", "pl",
        "html", "htm", "xhtml", "shtml",
        "js", "mjs", "cjs", "ts", "jsx", "tsx",
        "css", "scss", "less",
        "json", "xml", "yaml", "yml", "toml",
        "txt", "csv", "log", "md",
        "jpg", "jpeg", "png", "gif", "svg", "ico", "webp", "bmp",
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "zip", "gz", "tar", "rar", "bz2",
        "mp3", "mp4", "avi", "mov", "webm", "ogg",
        "woff", "woff2", "ttf", "eot", "otf",
        "map", "wasm", "swf", "jar", "war",
        "py", "rb", "java", "class", "go", "rs",
        "sh", "bat", "cmd", "ps1",
        "sql", "db", "sqlite",
        "conf", "cfg", "ini", "env",
        "htaccess", "htpasswd",
        "bak", "old", "orig", "tmp", "swp"
    ));

    private String replaceDomains(String text) {
        Matcher m = DOMAIN_PATTERN.matcher(text);
        StringBuffer sb = new StringBuffer();
        Set<String> skip = new HashSet<>(Arrays.asList(
            "example.com", "target.example.com", "example.org", "example.net",
            "redacted.example.com"
        ));
        while (m.find()) {
            String domain = m.group(1).toLowerCase();

            // Skip already-redacted domains
            if (skip.contains(domain) || domain.endsWith(".example.com") ||
                domain.endsWith(".example.org") || domain.endsWith(".example.net")) {
                m.appendReplacement(sb, Matcher.quoteReplacement(m.group()));
                continue;
            }

            // Skip file extensions mistaken for TLDs (e.g., v2.php, script.js)
            int lastDot = domain.lastIndexOf('.');
            if (lastDot >= 0) {
                String tld = domain.substring(lastDot + 1);
                if (FILE_EXTENSIONS.contains(tld)) {
                    m.appendReplacement(sb, Matcher.quoteReplacement(m.group()));
                    continue;
                }
            }

            // Skip if preceded by / (URL path segment, not a real domain)
            int startPos = m.start();
            if (startPos > 0 && text.charAt(startPos - 1) == '/') {
                // Check if this is NOT a protocol:// prefix
                boolean isProtocol = (startPos >= 2 && text.charAt(startPos - 2) == '/');
                if (!isProtocol) {
                    m.appendReplacement(sb, Matcher.quoteReplacement(m.group()));
                    continue;
                }
            }

            String fullMatch = m.group(0);
            String replacement = fullMatch.replace(m.group(1), redactHost(m.group(1)));
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    // ==================== REDACTION HELPERS ====================

    private String redactHost(String host) {
        if (host == null || host.isEmpty()) return host;
        String cleanHost = host.contains(":") ? host.substring(0, host.indexOf(':')) : host;
        String port = host.contains(":") ? host.substring(host.indexOf(':')) : "";

        String key = cleanHost.toLowerCase();
        if (!hostMap.containsKey(key)) {
            if (hostCounter == 1) {
                hostMap.put(key, "target.example.com");
            } else {
                hostMap.put(key, "host" + hostCounter + ".example.com");
            }
            hostCounter++;
        }
        return hostMap.get(key) + port;
    }

    private String getHostMapping(String host) {
        String key = host.toLowerCase();
        return hostMap.getOrDefault(key, redactHost(host));
    }

    private String redactCookieName(String name) {
        String key = name.toLowerCase();
        if (!cookieNameMap.containsKey(key)) {
            cookieNameMap.put(key, "cookie" + cookieNameCounter);
            cookieNameCounter++;
        }
        return cookieNameMap.get(key);
    }

    private String redactCookieValue(String value) {
        if (!cookieValueMap.containsKey(value)) {
            cookieValueMap.put(value, "cookieval" + cookieValueCounter);
            cookieValueCounter++;
        }
        return cookieValueMap.get(value);
    }

    private String redactTokenValue(String headerName, String value) {
        String key = headerName.toLowerCase() + ":" + value;
        if (!headerValueMap.containsKey(key)) {
            headerValueMap.put(key, "REDACTED_TOKEN_" + tokenCounter);
            tokenCounter++;
        }
        return headerValueMap.get(key);
    }

    private String redactParamValue(String value) {
        if (!paramValueMap.containsKey(value)) {
            paramValueMap.put(value, "REDACTED_PARAM_" + paramCounter);
            paramCounter++;
        }
        return paramValueMap.get(value);
    }

    private String redactUuid(String uuid) {
        String key = uuid.toLowerCase();
        if (!uuidMap.containsKey(key)) {
            uuidMap.put(key, String.format("00000000-0000-0000-0000-%012d", uuidCounter));
            uuidCounter++;
        }
        return uuidMap.get(key);
    }

    private String redactIp(String ip) {
        if (!ipMap.containsKey(ip)) {
            ipMap.put(ip, "10.0.0." + ipCounter);
            ipCounter++;
        }
        return ipMap.get(ip);
    }

    private String redactEmail(String email) {
        if (!emailMap.containsKey(email.toLowerCase())) {
            emailMap.put(email.toLowerCase(), "user" + emailCounter + "@redacted.example.com");
            emailCounter++;
        }
        return emailMap.get(email.toLowerCase());
    }

    private String redactJwt(String jwt) {
        if (!jwtMap.containsKey(jwt)) {
            jwtMap.put(jwt, "REDACTED_JWT_TOKEN_" + jwtCounter);
            jwtCounter++;
        }
        return jwtMap.get(jwt);
    }

    private String redactNonce(String nonce) {
        if (!nonceMap.containsKey(nonce)) {
            nonceMap.put(nonce, "REDACTED_NONCE_" + nonceCounter);
            nonceCounter++;
        }
        return nonceMap.get(nonce);
    }

    private String redactNonceOrToken(String value) {
        if (!nonceMap.containsKey(value)) {
            nonceMap.put(value, "REDACTED_REQUEST_TOKEN_" + nonceCounter);
            nonceCounter++;
        }
        return nonceMap.get(value);
    }

    private String redactEtagValue(String value) {
        if (!etagMap.containsKey(value)) {
            etagMap.put(value, "\"REDACTED_ETAG_" + etagCounter + "\"");
            etagCounter++;
        }
        return etagMap.get(value);
    }

    private String redactBase64Token(String token) {
        if (!base64Map.containsKey(token)) {
            base64Map.put(token, "REDACTED_BASE64_TOKEN_" + base64Counter);
            base64Counter++;
        }
        return base64Map.get(token);
    }

    private String redactHexToken(String token) {
        if (!hexTokenMap.containsKey(token.toLowerCase())) {
            hexTokenMap.put(token.toLowerCase(), "REDACTED_HEX_TOKEN_" + hexTokenCounter);
            hexTokenCounter++;
        }
        return hexTokenMap.get(token.toLowerCase());
    }

    private String redactUsername(String username) {
        String key = username.toLowerCase();
        if (!usernameMap.containsKey(key)) {
            usernameMap.put(key, "REDACTED_USER_" + usernameCounter);
            usernameCounter++;
        }
        return usernameMap.get(key);
    }


    private String redactPan(String pan) {
        if (!panMap.containsKey(pan)) {
            panMap.put(pan, "REDACTED_CARD_PAN_" + panCounter);
            panCounter++;
        }
        return panMap.get(pan);
    }

    private String redactIban(String iban) {
        String key = iban.toUpperCase().replaceAll("\\s", "");
        if (!ibanMap.containsKey(key)) {
            ibanMap.put(key, "REDACTED_IBAN_" + ibanCounter);
            ibanCounter++;
        }
        return ibanMap.get(key);
    }

    private String redactPhone(String phone) {
        if (!phoneMap.containsKey(phone)) {
            phoneMap.put(phone, "REDACTED_PHONE_" + phoneCounter);
            phoneCounter++;
        }
        return phoneMap.get(phone);
    }

    private String redactSsn(String ssn) {
        if (!ssnMap.containsKey(ssn)) {
            ssnMap.put(ssn, "REDACTED_SSN_" + ssnCounter);
            ssnCounter++;
        }
        return ssnMap.get(ssn);
    }

    private String redactGovId(String id, String type) {
        String key = type + ":" + id;
        if (!govIdMap.containsKey(key)) {
            govIdMap.put(key, "REDACTED_" + type + "_" + govIdCounter);
            govIdCounter++;
        }
        return govIdMap.get(key);
    }

    private String redactCoord(String coord) {
        if (!coordMap.containsKey(coord)) {
            coordMap.put(coord, "REDACTED_COORDINATES_" + coordCounter);
            coordCounter++;
        }
        return coordMap.get(coord);
    }

    // ==================== UTILITY ====================

    private boolean isSensitiveParam(String name) {
        if (name == null) return false;
        String lower = name.toLowerCase().trim();
        if (SENSITIVE_PARAMS.contains(lower)) return true;
        // Partial match for compound names like "user_password", "auth_token"
        for (String sensitive : SENSITIVE_PARAMS) {
            if (sensitive.length() >= 3 && lower.contains(sensitive)) {
                if (lower.length() >= 3) return true;
            }
        }
        return false;
    }

    private boolean looksLikeSecret(String value) {
        if (value == null || value.length() < 16) return false;
        // JWT
        if (JWT_PATTERN.matcher(value).find()) return true;
        // Long hex string
        if (value.matches("[0-9a-fA-F]{24,}")) return true;
        // Long base64-like string
        if (value.matches("[A-Za-z0-9+/=_\\-]{32,}")) return true;
        // Colon-separated base64 tokens (Requesttoken style)
        if (value.matches("[A-Za-z0-9+/=]{16,}:[A-Za-z0-9+/=]{16,}")) return true;
        // AWS key
        if (AWS_KEY_PATTERN.matcher(value).find()) return true;
        return false;
    }

    private String getContentType(List<String> headers) {
        for (String h : headers) {
            if (h.toLowerCase().startsWith("content-type:")) {
                return h.substring(13).trim().toLowerCase();
            }
        }
        return null;
    }

    // ==================== PATTERN REPLACEMENT HELPERS ====================

    @FunctionalInterface
    private interface GroupedMatchReplacer {
        String replace(Matcher m);
    }

    private String replaceAllGrouped(String text, Pattern pattern, GroupedMatchReplacer replacer) {
        Matcher m = pattern.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            m.appendReplacement(sb, Matcher.quoteReplacement(replacer.replace(m)));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private String replaceIgnoreCase(String text, String search, String replacement) {
        if (search == null || search.isEmpty()) return text;
        Pattern p = Pattern.compile(Pattern.quote(search), Pattern.CASE_INSENSITIVE);
        return p.matcher(text).replaceAll(Matcher.quoteReplacement(replacement));
    }
}
