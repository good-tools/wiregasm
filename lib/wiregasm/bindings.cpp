#include "wiregasm.h"

#include <emscripten/bind.h>

using namespace emscripten;

EMSCRIPTEN_BINDINGS(Wiregasm)
{
  emscripten::function("init", &wg_init);
  emscripten::function("reloadLuaPlugins", &wg_reload_lua_plugins);
  emscripten::function("destroy", &wg_destroy);
  emscripten::function("getColumns", &wg_get_columns);
  emscripten::function("upload", &wg_upload_file, allow_raw_pointers());
  emscripten::function("checkFilter", &wg_check_filter);
  emscripten::function("completeFilter", &wg_complete_filter);
  emscripten::function("getUploadDirectory", &wg_get_upload_dir);
  emscripten::function("getPluginsDirectory", &wg_get_plugins_dir);
  emscripten::function("setPref", &wg_set_pref);
  emscripten::function("getPref", &wg_get_pref);
  emscripten::function("listModules", &wg_list_modules);
  emscripten::function("listPreferences", &wg_list_preferences);
  emscripten::function("applyPreferences", &wg_prefs_apply_all);
}

EMSCRIPTEN_BINDINGS(TapResponse)
{
  value_object<TapResponse>("TapResponse")
    .field("taps", &TapResponse::taps)
    .field("error", &TapResponse::error);
}

EMSCRIPTEN_BINDINGS(ExportObject)
{
  value_object<eo::ExportObject>("ExportObject")
    .field("pkt", &eo::ExportObject::pkt)
    .field("hostname", &eo::ExportObject::hostname)
    .field("type", &eo::ExportObject::type)
    .field("len", &eo::ExportObject::len)
    .field("filename", &eo::ExportObject::filename)
    .field("_download", &eo::ExportObject::_download);
}

EMSCRIPTEN_BINDINGS(ExportObjectTap)
{
  value_object<eo::ExportObjectTap>("ExportObjectTap")
    .field("tap", &eo::ExportObjectTap::tap)
    .field("type", &eo::ExportObjectTap::type)
    .field("proto", &eo::ExportObjectTap::proto)
    .field("objects", &eo::ExportObjectTap::objects);
}

EMSCRIPTEN_BINDINGS(DissectSession)
{
  class_<DissectSession>("DissectSession")
    .constructor<std::string>()
    .function("load", &DissectSession::load)
    .function("getFrames", &DissectSession::getFrames)
    .function("getFrame", &DissectSession::getFrame)
    .function("tap", &DissectSession::tap)
    .function("download", &DissectSession::download)
    .function("follow", &DissectSession::follow);
}

EMSCRIPTEN_BINDINGS(ProtoTree)
{
  value_object<ProtoTree>("ProtoTree")
    .field("label", &ProtoTree::label)
    .field("filter", &ProtoTree::filter)
    .field("start", &ProtoTree::start)
    .field("length", &ProtoTree::length)
    .field("data_source_idx", &ProtoTree::data_source_idx)
    .field("tree", &ProtoTree::tree)
    .field("severity", &ProtoTree::severity)
    .field("type", &ProtoTree::type)
    .field("fnum", &ProtoTree::fnum)
    .field("url", &ProtoTree::url);
}

EMSCRIPTEN_BINDINGS(PrefData)
{
  value_object<PrefData>("PrefData")
    .field("name", &PrefData::name)
    .field("title", &PrefData::title)
    .field("description", &PrefData::description)
    .field("type", &PrefData::type)
    .field("uint_value", &PrefData::uint_value)
    .field("uint_base_value", &PrefData::uint_base_value)
    .field("bool_value", &PrefData::bool_value)
    .field("string_value", &PrefData::string_value)
    .field("enum_value", &PrefData::enum_value)
    .field("range_value", &PrefData::range_value);
}

EMSCRIPTEN_BINDINGS(PrefResponse)
{
  value_object<PrefResponse>("PrefResponse")
    .field("code", &PrefResponse::code)
    .field("data", &PrefResponse::data);
}

EMSCRIPTEN_BINDINGS(SetPrefResponse)
{
  value_object<SetPrefResponse>("SetPrefResponse")
    .field("code", &SetPrefResponse::code)
    .field("error", &SetPrefResponse::error);
}

EMSCRIPTEN_BINDINGS(PrefEnum)
{
  value_object<PrefEnum>("PrefEnum")
    .field("name", &PrefEnum::name)
    .field("description", &PrefEnum::description)
    .field("value", &PrefEnum::value)
    .field("selected", &PrefEnum::selected);
}

EMSCRIPTEN_BINDINGS(PrefModule)
{
  value_object<PrefModule>("PrefModule")
    .field("name", &PrefModule::name)
    .field("title", &PrefModule::title)
    .field("description", &PrefModule::description)
    .field("submodules", &PrefModule::submodules)
    .field("use_gui", &PrefModule::use_gui);
}

EMSCRIPTEN_BINDINGS(DataSource)
{
  value_object<DataSource>("DataSource")
    .field("name", &DataSource::name)
    .field("data", &DataSource::data);
}

EMSCRIPTEN_BINDINGS(Frame)
{
  value_object<Frame>("Frame")
    .field("number", &Frame::number)
    .field("comments", &Frame::comments)
    .field("data_sources", &Frame::data_sources)
    .field("tree", &Frame::tree)
    .field("follow", &Frame::follow);
}

EMSCRIPTEN_BINDINGS(FrameMeta)
{
  value_object<FrameMeta>("FrameMeta")
    .field("number", &FrameMeta::number)
    .field("comments", &FrameMeta::comments)
    .field("ignored", &FrameMeta::ignored)
    .field("marked", &FrameMeta::marked)
    .field("bg", &FrameMeta::bg)
    .field("fg", &FrameMeta::fg)
    .field("columns", &FrameMeta::columns);
}

EMSCRIPTEN_BINDINGS(LoadResponse)
{
  value_object<LoadResponse>("LoadResponse")
    .field("code", &LoadResponse::code)
    .field("error", &LoadResponse::error)
    .field("summary", &LoadResponse::summary);
}

EMSCRIPTEN_BINDINGS(FramesResponse)
{
  value_object<FramesResponse>("FramesResponse")
    .field("frames", &FramesResponse::frames)
    .field("matched", &FramesResponse::matched);
}

EMSCRIPTEN_BINDINGS(CheckFilterResponse)
{
  value_object<CheckFilterResponse>("CheckFilterResponse")
    .field("ok", &CheckFilterResponse::ok)
    .field("error", &CheckFilterResponse::error);
}

EMSCRIPTEN_BINDINGS(FilterCompletionResponse)
{
  value_object<FilterCompletionResponse>("FilterCompletionResponse")
    .field("fields", &FilterCompletionResponse::fields);
}

EMSCRIPTEN_BINDINGS(Summary)
{
  value_object<Summary>("Summary")
    .field("filename", &Summary::filename)
    .field("file_type", &Summary::file_type)
    .field("file_length", &Summary::file_length)
    .field("file_encap_type", &Summary::file_encap_type)
    .field("packet_count", &Summary::packet_count)
    .field("start_time", &Summary::start_time)
    .field("stop_time", &Summary::stop_time)
    .field("elapsed_time", &Summary::elapsed_time);
}

EMSCRIPTEN_BINDINGS(FollowPayload)
{
  value_object<FollowPayload>("FollowPayload")
    .field("number", &FollowPayload::number)
    .field("data", &FollowPayload::data)
    .field("server", &FollowPayload::server);
}

EMSCRIPTEN_BINDINGS(Follow)
{
  value_object<Follow>("Follow")
    .field("shost", &Follow::shost)
    .field("sport", &Follow::sport)
    .field("sbytes", &Follow::sbytes)
    .field("chost", &Follow::chost)
    .field("cport", &Follow::cport)
    .field("cbytes", &Follow::cbytes)
    .field("payloads", &Follow::payloads);
}

EMSCRIPTEN_BINDINGS(CompleteField)
{
  value_object<CompleteField>("CompleteField")
    .field("field", &CompleteField::field)
    .field("type", &CompleteField::type)
    .field("name", &CompleteField::name);
}

EMSCRIPTEN_BINDINGS(stl_wrappers)
{
  register_vector<string>("VectorString");
  register_vector<FrameMeta>("VectorFrameMeta");
  register_vector<DataSource>("VectorDataSource");
  register_vector<ProtoTree>("VectorProtoTree");
  register_vector<FollowPayload>("VectorFollowPayload");
  register_vector<CompleteField>("VectorCompleteField");
  register_vector<PrefModule>("VectorPrefModule");
  register_vector<PrefData>("VectorPrefData");
  register_vector<PrefEnum>("VectorPrefEnum");
  // Frame::follow is a vector of vectors of strings
  register_vector<vector<string>>("VectorVectorString");
  register_vector<eo::ExportObject>("VectorExportObject");
  register_vector<eo::ExportObjectTap>("VectorExportObjectTap");
  register_map<string, string>("map<string, string>");
}

EMSCRIPTEN_BINDINGS(Download)
{
  value_object<Download>("Download")
    .field("file", &Download::file)
    .field("mime", &Download::mime)
    .field("data", &Download::data);
}

EMSCRIPTEN_BINDINGS(DownloadResponse)
{
  value_object<DownloadResponse>("DownloadResponse")
    .field("error", &DownloadResponse::error)
    .field("download", &DownloadResponse::download);
}
