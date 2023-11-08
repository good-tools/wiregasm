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
  emscripten::function("getUploadDirectory", &wg_get_upload_dir);
  emscripten::function("getPluginsDirectory", &wg_get_plugins_dir);
}

EMSCRIPTEN_BINDINGS(DissectSession)
{
  class_<DissectSession>("DissectSession")
      .constructor<std::string>()
      .function("load", &DissectSession::load)
      .function("getFrames", &DissectSession::getFrames)
      .function("getFrame", &DissectSession::getFrame);
}

EMSCRIPTEN_BINDINGS(ProtoTree)
{
  value_object<ProtoTree>("ProtoTree")
      .field("label", &ProtoTree::label)
      .field("filter", &ProtoTree::filter)
      .field("start", &ProtoTree::start)
      .field("length", &ProtoTree::length)
      .field("data_source_idx", &ProtoTree::data_source_idx)
      .field("tree", &ProtoTree::tree);
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
      .field("tree", &Frame::tree);
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

EMSCRIPTEN_BINDINGS(stl_wrappers)
{
  register_vector<string>("VectorString");
  register_vector<FrameMeta>("VectorFrameMeta");
  register_vector<DataSource>("VectorDataSource");
  register_vector<ProtoTree>("VectorProtoTree");
}
