#include <arpa/inet.h>

#include <sstream>

#include "ServiceContext.h"

ServiceContext::ServiceContext()
    : port(1000)
    , user("admin")
    , password("admin")
    ,

    // Device Information
    manufacturer("Manufacturer")
    , model("Model")
    , firmware_version("FirmwareVersion")
    , serial_number("SerialNumber")
    , hardware_id("HardwareId")
{
}

std::string ServiceContext::getServerIpFromClientIp(uint32_t client_ip) const
{
    char server_ip[INET_ADDRSTRLEN];

    for (size_t i = 0; i < eth_ifs.size(); ++i) {
        uint32_t if_ip, if_mask;
        eth_ifs[i].get_ip(&if_ip);
        eth_ifs[i].get_mask(&if_mask);

        if ((if_ip & if_mask) == (client_ip & if_mask)) {
            eth_ifs[i].get_ip(server_ip);
            return server_ip;
        }
    }

    return "127.0.0.1"; // localhost
}

std::string ServiceContext::getXAddr(soap* soap) const
{
    std::ostringstream os;

    os << "http://" << getServerIpFromClientIp(htonl(soap->ip)) << ":" << port;

    return os.str();
}

bool ServiceContext::add_profile(const StreamProfile& profile)
{
    if (!profile.is_valid()) {
        str_err = "profile has unset parameters";
        return false;
    }

    if (profiles.find(profile.get_name()) != profiles.end()) {
        str_err = "profile: " + profile.get_name() + " already exist";
        return false;
    }

    profiles[profile.get_name()] = profile;
    return true;
}

std::string ServiceContext::get_stream_uri(const std::string& profile_url, uint32_t client_ip) const
{
    std::string uri(profile_url);
    std::string template_str("%s");

    auto it = uri.find(template_str, 0);

    if (it != std::string::npos)
        uri.replace(it, template_str.size(), getServerIpFromClientIp(client_ip));

    return uri;
}

std::string ServiceContext::get_snapshot_uri(
    const std::string& profile_url, uint32_t client_ip) const
{
    std::string uri(profile_url);
    std::string template_str("%s");

    auto it = uri.find(template_str, 0);

    if (it != std::string::npos)
        uri.replace(it, template_str.size(), getServerIpFromClientIp(client_ip));

    return uri;
}

tds__DeviceServiceCapabilities* ServiceContext::getDeviceServiceCapabilities(soap* soap)
{
    tds__DeviceServiceCapabilities* capabilities = soap_new_req_tds__DeviceServiceCapabilities(soap,
        soap_new_req_tds__NetworkCapabilities(soap), soap_new_req_tds__SecurityCapabilities(soap),
        soap_new_req_tds__SystemCapabilities(soap));

    capabilities->Network->IPFilter = soap_new_ptr(soap, true);
    capabilities->Network->ZeroConfiguration = soap_new_ptr(soap, true);
    capabilities->Network->IPVersion6 = soap_new_ptr(soap, false);
    capabilities->Network->DynDNS = soap_new_ptr(soap, true);
    capabilities->Network->Dot11Configuration = soap_new_ptr(soap, true);
    capabilities->Network->Dot1XConfigurations = soap_new_ptr(soap, 1);
    capabilities->Network->HostnameFromDHCP = soap_new_ptr(soap, true);
    capabilities->Network->NTP = soap_new_ptr(soap, 2);
    capabilities->Network->DHCPv6 = soap_new_ptr(soap, false);

    capabilities->Security->TLS1_x002e0 = soap_new_ptr(soap, false);
    capabilities->Security->TLS1_x002e1 = soap_new_ptr(soap, false);
    capabilities->Security->TLS1_x002e2 = soap_new_ptr(soap, false);
    capabilities->Security->OnboardKeyGeneration = soap_new_ptr(soap, false);
    capabilities->Security->AccessPolicyConfig = soap_new_ptr(soap, true);
    capabilities->Security->DefaultAccessPolicy = soap_new_ptr(soap, true);
    capabilities->Security->Dot1X = soap_new_ptr(soap, true);
    capabilities->Security->RemoteUserHandling = soap_new_ptr(soap, true);
    capabilities->Security->X_x002e509Token = soap_new_ptr(soap, false);
    capabilities->Security->SAMLToken = soap_new_ptr(soap, false);
    capabilities->Security->KerberosToken = soap_new_ptr(soap, false);
    capabilities->Security->UsernameToken = soap_new_ptr(soap, true);
    capabilities->Security->HttpDigest = soap_new_ptr(soap, true);
    capabilities->Security->RELToken = soap_new_ptr(soap, false);
    capabilities->Security->MaxUsers = soap_new_ptr(soap, 10);
    capabilities->Security->MaxUserNameLength = soap_new_ptr(soap, 32);
    capabilities->Security->MaxPasswordLength = soap_new_ptr(soap, 32);

    capabilities->System->DiscoveryResolve = soap_new_ptr(soap, true);
    capabilities->System->DiscoveryBye = soap_new_ptr(soap, true);
    capabilities->System->RemoteDiscovery = soap_new_ptr(soap, true);
    capabilities->System->SystemBackup = soap_new_ptr(soap, true);
    capabilities->System->SystemLogging = soap_new_ptr(soap, true);
    capabilities->System->FirmwareUpgrade = soap_new_ptr(soap, true);
    capabilities->System->HttpFirmwareUpgrade = soap_new_ptr(soap, true);
    capabilities->System->HttpSystemBackup = soap_new_ptr(soap, true);
    capabilities->System->HttpSystemLogging = soap_new_ptr(soap, true);
    capabilities->System->HttpSupportInformation = soap_new_ptr(soap, true);
    capabilities->System->StorageConfiguration = soap_new_ptr(soap, false);

    capabilities->Misc = soap_new_req_tds__MiscCapabilities(soap);

    return capabilities;
}

trt__Capabilities* ServiceContext::getMediaServiceCapabilities(soap* soap)
{
    trt__Capabilities* capabilities = soap_new_req_trt__Capabilities(soap,
        soap_new_req_trt__ProfileCapabilities(soap), soap_new_req_trt__StreamingCapabilities(soap));

    auto profiles = this->get_profiles();
    for (auto& it : profiles) {
        if ((!it.second.get_snapurl().empty()) && (capabilities->SnapshotUri == NULL)) {
            capabilities->SnapshotUri = soap_new_ptr(soap, true);
        }
    }

    capabilities->ProfileCapabilities->MaximumNumberOfProfiles = soap_new_ptr(soap, 1);
    capabilities->StreamingCapabilities->RTPMulticast = soap_new_ptr(soap, false);

    return capabilities;
}

tptz__Capabilities* ServiceContext::getPTZServiceCapabilities(soap* soap)
{
    tptz__Capabilities* capabilities = soap_new_req_tptz__Capabilities(soap);

    return capabilities;
}

// ------------------------------- StreamProfile -------------------------------

tt__VideoSourceConfiguration* StreamProfile::get_video_src_cnf(struct soap* soap) const
{
    const std::string cfg_name = name + "_CFG";

    tt__VideoSourceConfiguration* src_cfg
        = soap_new_req_tt__VideoSourceConfiguration(soap, name + "_SRC",
            soap_new_req_tt__IntRectangle(soap, 0, 0, width, height), cfg_name, 1, cfg_name);

    return src_cfg;
}

tt__VideoEncoderConfiguration* StreamProfile::get_video_enc_cfg(struct soap* soap) const
{
    const std::string enc_name = name + "_ENC";

    tt__VideoEncoderConfiguration* enc_cfg
        = soap_new_req_tt__VideoEncoderConfiguration(soap, static_cast<tt__VideoEncoding>(type),
            soap_new_req_tt__VideoResolution(soap, width, height), 4,
            soap_new_req_tt__MulticastConfiguration(
                soap, soap_new_req_tt__IPAddress(soap, tt__IPType__IPv4), 32002, 2, false),
            0, enc_name, 1, enc_name);

    enc_cfg->RateControl = soap_new_req_tt__VideoRateControl(soap, 25, 50, 2048);
    enc_cfg->Multicast->Address->IPv4Address = &(soap_new_std__string(soap)->assign("239.0.1.0"));
    enc_cfg->H264 = soap_new_req_tt__H264Configuration(soap, 50, tt__H264Profile__Main);

    return enc_cfg;
}

tt__PTZConfiguration* StreamProfile::get_ptz_cfg(struct soap* soap) const
{
    tt__PTZConfiguration* ptz_cfg
        = soap_new_req_tt__PTZConfiguration(soap, "PTZNodeToken", "PTZ", 1, "PTZToken");

    ptz_cfg->DefaultAbsolutePantTiltPositionSpace = &(soap_new_std__string(soap)->assign(
        "http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace"));
    ptz_cfg->DefaultAbsoluteZoomPositionSpace = &(soap_new_std__string(soap)->assign(
        "http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace"));
    ptz_cfg->DefaultRelativePanTiltTranslationSpace = &(soap_new_std__string(soap)->assign(
        "http://www.onvif.org/ver10/tptz/PanTiltSpaces/TranslationGenericSpace"));
    ptz_cfg->DefaultRelativeZoomTranslationSpace = &(soap_new_std__string(soap)->assign(
        "http://www.onvif.org/ver10/tptz/ZoomSpaces/TranslationGenericSpace"));
    ptz_cfg->DefaultContinuousPanTiltVelocitySpace = &(soap_new_std__string(soap)->assign(
        "http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace"));
    ptz_cfg->DefaultContinuousZoomVelocitySpace = &(soap_new_std__string(soap)->assign(
        "http://www.onvif.org/ver10/tptz/ZoomSpaces/VelocityGenericSpace"));

    ptz_cfg->DefaultPTZSpeed = soap_new_req_tt__PTZSpeed(soap);
    ptz_cfg->DefaultPTZSpeed->PanTilt = soap_new_req_tt__Vector2D(soap, 0.1, 0.1);
    ptz_cfg->DefaultPTZSpeed->Zoom = soap_new_req_tt__Vector1D(soap, 1);

    ptz_cfg->DefaultPTZTimeout = (LONG64*)soap_malloc(soap, sizeof(LONG64));
    soap_s2xsd__duration(soap, "1000", ptz_cfg->DefaultPTZTimeout);

    ptz_cfg->PanTiltLimits = soap_new_req_tt__PanTiltLimits(soap,
        soap_new_req_tt__Space2DDescription(soap,
            "http://www.onvif.org/ver10/tptz/PanTiltSpaces/PositionGenericSpace",
            soap_new_req_tt__FloatRange(soap, -1.0, 1.0),
            soap_new_req_tt__FloatRange(soap, -1.0, 1.0)));

    ptz_cfg->ZoomLimits = soap_new_req_tt__ZoomLimits(soap,
        soap_new_req_tt__Space1DDescription(soap,
            "http://www.onvif.org/ver10/tptz/ZoomSpaces/PositionGenericSpace",
            soap_new_req_tt__FloatRange(soap, 0.0, 1.0)));

    return ptz_cfg;
}

tt__Profile* StreamProfile::get_profile(struct soap* soap) const
{
    ServiceContext* ctx = (ServiceContext*)soap->user;

    tt__Profile* profile = soap_new_req_tt__Profile(soap, name, name);

    profile->VideoSourceConfiguration = get_video_src_cnf(soap);
    profile->VideoEncoderConfiguration = get_video_enc_cfg(soap);
    if (ctx->get_ptz_node()->get_enable() == true) {
        profile->PTZConfiguration = get_ptz_cfg(soap);
    }

    return profile;
}

tt__VideoSource* StreamProfile::get_video_src(soap* soap) const
{
    tt__VideoSource* video_src = soap_new_req_tt__VideoSource(
        soap, 25, soap_new_req_tt__VideoResolution(soap, width, height), name);

    video_src->Imaging = soap_new_req_tt__ImagingSettings(soap);
    video_src->Imaging->BacklightCompensation
        = soap_new_req_tt__BacklightCompensation(soap, tt__BacklightCompensationMode__OFF, 10.0);
    video_src->Imaging->Brightness = soap_new_ptr(soap, 50.0f);
    video_src->Imaging->ColorSaturation = soap_new_ptr(soap, 50.0f);
    video_src->Imaging->Contrast = soap_new_ptr(soap, 50.0f);
    video_src->Imaging->Exposure
        = soap_new_req_tt__Exposure(soap, tt__ExposureMode__AUTO, tt__ExposurePriority__LowNoise,
            soap_new_set_tt__Rectangle(soap, soap_new_ptr(soap, 1.0f), soap_new_ptr(soap, 0.0f),
                soap_new_ptr(soap, 1.0f), soap_new_ptr(soap, 0.0f)),
            10.0, 40000.0, 0.0, 100.0, 0.0, 10.0, 4000.0, 100.0, 10.0);
    video_src->Imaging->Focus
        = soap_new_req_tt__FocusConfiguration(soap, tt__AutoFocusMode__AUTO, 100.0, 0.0, 100.0);
    video_src->Imaging->IrCutFilter = soap_new_ptr(soap, tt__IrCutFilterMode__AUTO);
    video_src->Imaging->Sharpness = soap_new_ptr(soap, 50.0f);
    video_src->Imaging->WideDynamicRange
        = soap_new_req_tt__WideDynamicRange(soap, tt__WideDynamicMode__OFF, 50.0);
    video_src->Imaging->WhiteBalance
        = soap_new_req_tt__WhiteBalance(soap, tt__WhiteBalanceMode__AUTO, 10.0, 10.0);

    return video_src;
}

bool StreamProfile::set_name(const char* new_val)
{
    if (!new_val) {
        str_err = "Name is empty";
        return false;
    }

    name = new_val;
    return true;
}

bool StreamProfile::set_width(const char* new_val)
{

    std::istringstream ss(new_val);
    int tmp_val;
    ss >> tmp_val;

    if ((tmp_val < 100) || (tmp_val >= 10000)) {
        str_err = "width is bad, correct range: 100-10000";
        return false;
    }

    width = tmp_val;
    return true;
}

bool StreamProfile::set_height(const char* new_val)
{
    std::istringstream ss(new_val);
    int tmp_val;
    ss >> tmp_val;

    if ((tmp_val < 100) || (tmp_val >= 10000)) {
        str_err = "height is bad, correct range: 100-10000";
        return false;
    }

    height = tmp_val;
    return true;
}

bool StreamProfile::set_url(const char* new_val)
{
    if (!new_val) {
        str_err = "URL is empty";
        return false;
    }

    url = new_val;
    return true;
}

bool StreamProfile::set_snapurl(const char* new_val)
{
    if (!new_val) {
        str_err = "URL is empty";
        return false;
    }

    snapurl = new_val;
    return true;
}

bool StreamProfile::set_type(const char* new_val)
{
    std::string new_type(new_val);

    if (new_type == "JPEG")
        type = tt__VideoEncoding__JPEG;
    else if (new_type == "MPEG4")
        type = tt__VideoEncoding__MPEG4;
    else if (new_type == "H264")
        type = tt__VideoEncoding__H264;
    else {
        str_err = "type dont support";
        return false;
    }

    return true;
}

void StreamProfile::clear()
{
    name.clear();
    url.clear();
    snapurl.clear();

    width = -1;
    height = -1;
    type = -1;
}

bool StreamProfile::is_valid() const
{
    return (!name.empty() && !url.empty() && (width != -1) && (height != -1) && (type != -1));
}

bool PTZNode::set_enable(bool val)
{
    enable = val;
    return true;
}

bool PTZNode::set_move_left(const char* new_val)
{
    if (!new_val) {
        str_err = "Process is empty";
        return false;
    }

    move_left = new_val;
    return true;
}

bool PTZNode::set_move_right(const char* new_val)
{
    if (!new_val) {
        str_err = "Process is empty";
        return false;
    }

    move_right = new_val;
    return true;
}

bool PTZNode::set_move_up(const char* new_val)
{
    if (!new_val) {
        str_err = "Process is empty";
        return false;
    }

    move_up = new_val;
    return true;
}

bool PTZNode::set_move_down(const char* new_val)
{
    if (!new_val) {
        str_err = "Process is empty";
        return false;
    }

    move_down = new_val;
    return true;
}

bool PTZNode::set_move_stop(const char* new_val)
{
    if (!new_val) {
        str_err = "Process is empty";
        return false;
    }

    move_stop = new_val;
    return true;
}

bool PTZNode::set_move_preset(const char* new_val)
{
    if (!new_val) {
        str_err = "Process is empty";
        return false;
    }

    move_preset = new_val;
    return true;
}

void PTZNode::clear()
{
    enable = false;

    move_left.clear();
    move_right.clear();
    move_up.clear();
    move_down.clear();
    move_stop.clear();
}
