#ifndef WIREGASM_DECODE_AS_H
#define WIREGASM_DECODE_AS_H

#include <string>
#include <vector>
#include <glib.h>
#include <wireshark/cfile.h>
#include <wireshark/epan/packet.h>
#include <wireshark/epan/decode_as.h>

using namespace std;

struct UIDecodeAsItem;

class WGDecodeAsItem
{
public:
  WGDecodeAsItem(const char *table_name = NULL, gconstpointer selector = NULL);
  WGDecodeAsItem(const decode_as_t *entry, gconstpointer selector = NULL);
  virtual ~WGDecodeAsItem();

  const char* tableName() const { return tableName_; }
  const char* tableUIName() const { return tableUIName_; }
  UIDecodeAsItem data();
  uint selectorUint() const { return selectorUint_; }
  string selectorString() const { return selectorString_; }
  string defaultDissector() const { return default_dissector_; }
  string currentDissector() const { return current_dissector_; }
  dissector_handle_t dissectorHandle() const { return dissector_handle_; }
  void setTable(const decode_as_t *entry);
  void setSelector(const string &value);
  void setDissectorHandle(dissector_handle_t handle);

  void updateHandles();
private:
  void init(const char *table_name, gconstpointer selector = NULL);
  string entryString(const char *table_name, gconstpointer value);

  const char* tableName_;
  const char* tableUIName_;

  uint selectorUint_;
  string selectorString_;

  // TODO: DCERPC

  string default_dissector_;
  string current_dissector_;
  dissector_handle_t dissector_handle_;
};

class WGDecodeAsModel
{
public:
  WGDecodeAsModel(capture_file *cf = NULL);
  virtual ~WGDecodeAsModel();
  void fillTable();
  void clearAll();
  int rowCount() const;
  bool insertRows(int row, int count);
  // void setDissectorHandle(const uint index, dissector_handle_t dissector_handle);
  void applyChanges();
  vector<UIDecodeAsItem> getUIModel();
protected:
  static void buildChangedList(const char *table_name, ftenum_t selector_type,
                        void *key, void *value, void *user_data);
  static void gatherChangedEntries(const char *table_name, ftenum_t selector_type,
                        void *key, void *value, void *user_data);
private:
  capture_file *cap_file_;
  vector<WGDecodeAsItem *> decode_as_items_;
  vector<pair<const char *, uint32_t> > changed_uint_entries_;
  vector<pair<const char *, const char *> > changed_string_entries_;
};

struct UIDecodeAsItem
{
  string field;
  string value;
  string default_dissector;
  string current_dissector;
};

#endif
