#include "wg_decode_as.h"
#include <wireshark/epan/ftypes/ftypes.h>
#include <wireshark/epan/prefs-int.h>
#include <epan/epan_dissect.h>

// impl copied from /ui/qt/models/decode_as_model.cpp

static const char *DEFAULT_TABLE = "tcp.port";    // Arbitrary
static const char *DEFAULT_UI_TABLE = "TCP port"; // Arbitrary

WGDecodeAsItem::WGDecodeAsItem(const char *table_name, gconstpointer selector) : tableName_(DEFAULT_TABLE),
                                                                                 tableUIName_(DEFAULT_UI_TABLE),
                                                                                 selectorUint_(0),
                                                                                 selectorString_(""),
                                                                                 default_dissector_(DECODE_AS_NONE),
                                                                                 current_dissector_(DECODE_AS_NONE),
                                                                                 dissector_handle_(NULL)
{
  if (table_name == nullptr)
    return;

  init(table_name, selector);
}

WGDecodeAsItem::WGDecodeAsItem(const decode_as_t *entry, gconstpointer selector) : tableName_(DEFAULT_TABLE),
                                                                                   tableUIName_(DEFAULT_UI_TABLE),
                                                                                   selectorUint_(0),
                                                                                   selectorString_(""),
                                                                                   //  selectorDCERPC_(NULL),
                                                                                   default_dissector_(DECODE_AS_NONE),
                                                                                   current_dissector_(DECODE_AS_NONE),
                                                                                   dissector_handle_(NULL)
{
  if (entry == nullptr)
    return;

  init(entry->table_name, selector);
}

string WGDecodeAsItem::entryString(const char *table_name, gconstpointer value)
{
  string entry_str;
  ftenum_t selector_type = get_dissector_table_selector_type(table_name);

  switch (selector_type)
  {

  case FT_UINT8:
  case FT_UINT16:
  case FT_UINT24:
  case FT_UINT32:
  {
    uint num_val = GPOINTER_TO_UINT(value);
    switch (get_dissector_table_param(table_name))
    {

    case BASE_DEC:
    case BASE_HEX:
    case BASE_OCT:
      entry_str = std::to_string(num_val);
      break;
    }
    break;
  }

  case FT_STRING:
  case FT_STRINGZ:
  case FT_UINT_STRING:
  case FT_STRINGZPAD:
  case FT_STRINGZTRUNC:
    entry_str = string((const char *)value);
    break;

  case FT_GUID:
    // avoid the assert for now
    break;

  case FT_NONE:
    // doesn't really matter, just avoiding the assert
    return "0";

  default:
    ws_assert_not_reached();
    break;
  }
  return entry_str;
}

UIDecodeAsItem WGDecodeAsItem::data()
{
  UIDecodeAsItem item;

  // field
  item.field = string(this->tableUIName());

  // value
  ftenum_t selector_type = get_dissector_table_selector_type(this->tableName());
  if (IS_FT_UINT(selector_type))
  {
    item.value = entryString(this->tableName(), GUINT_TO_POINTER(this->selectorUint()));
  }
  else if (IS_FT_STRING(selector_type))
  {
    item.value = entryString(this->tableName(), (gconstpointer)this->selectorString().c_str());
  }

  // default_dissector
  item.default_dissector = this->defaultDissector();

  // current_dissector
  item.current_dissector = this->currentDissector();

  return item;
}

WGDecodeAsItem::~WGDecodeAsItem()
{
}

void WGDecodeAsItem::init(const char *table_name, gconstpointer selector)
{
  tableName_ = table_name;
  tableUIName_ = get_dissector_table_ui_name(tableName_);

  dissector_handle_t default_handle = NULL;
  ftenum_t selector_type = get_dissector_table_selector_type(tableName_);
  if (IS_FT_STRING(selector_type))
  {
    if (selector != NULL)
    {
      default_handle = dissector_get_default_string_handle(tableName_, (const char *)selector);
      selectorString_ = string((const char *)selector);
    }
  }
  else if (IS_FT_UINT(selector_type))
  {
    if (selector != NULL)
    {
      selectorUint_ = GPOINTER_TO_UINT(selector);
      default_handle = dissector_get_default_uint_handle(tableName_, selectorUint_);
    }
  }
  else if (selector_type == FT_NONE)
  {
    // There is no default for an FT_NONE dissector table
  }
  else if (selector_type == FT_GUID)
  {
    /* Special handling for DCE/RPC dissectors */
    // if (strcmp(tableName_, DCERPC_TABLE_NAME) == 0)
    // {
    //   selectorDCERPC_ = (decode_dcerpc_bind_values_t *)(selector);
    // }
  }

  if (default_handle != NULL)
  {
    default_dissector_ = dissector_handle_get_description(default_handle);
    // When adding a new record, we set the "current" values equal to
    // the default, so the user can easily reset the value.
    // The existing value read from the prefs file should already
    // be added to the table from reading the prefs file.
    // When reading existing values the current dissector should be
    // set explicitly to the actual current value.
    current_dissector_ = default_dissector_;
    dissector_handle_ = default_handle;
  }
}

void WGDecodeAsItem::setTable(const decode_as_t *entry)
{
  if (entry == nullptr)
    return;

  tableName_ = entry->table_name;
  tableUIName_ = get_dissector_table_ui_name(entry->table_name);

  /* XXX: Should the selector values be reset (e.g., to 0 and "")
   * What if someone tries to change the table to the DCERPC table?
   * That doesn't really work without the DCERPC special handling.
   */

  updateHandles();
}

void WGDecodeAsItem::setSelector(const string &value)
{
  ftenum_t selector_type = get_dissector_table_selector_type(tableName_);

  if (IS_FT_STRING(selector_type))
  {
    selectorString_ = value;
  }
  else if (IS_FT_UINT(selector_type))
  {
    selectorUint_ = stoul(value, nullptr, 0);
  }

  updateHandles();
}

void WGDecodeAsItem::setDissectorHandle(dissector_handle_t handle)
{
  dissector_handle_ = handle;
  if (handle == nullptr)
  {
    current_dissector_ = DECODE_AS_NONE;
  }
  else
  {
    current_dissector_ = dissector_handle_get_description(handle);
  }
}

void WGDecodeAsItem::updateHandles()
{
  ftenum_t selector_type = get_dissector_table_selector_type(tableName_);
  dissector_handle_t default_handle = nullptr;

  if (IS_FT_STRING(selector_type))
  {
    default_handle = dissector_get_default_string_handle(tableName_, selectorString_.c_str());
  }
  else if (IS_FT_UINT(selector_type))
  {
    default_handle = dissector_get_default_uint_handle(tableName_, selectorUint_);
  }
  if (default_handle != nullptr)
  {
    default_dissector_ = dissector_handle_get_description(default_handle);
  }
  else
  {
    default_dissector_ = DECODE_AS_NONE;
  }
}

WGDecodeAsModel::WGDecodeAsModel(capture_file *cf)
{
  this->cap_file_ = cf;
}

WGDecodeAsModel::~WGDecodeAsModel()
{
  this->clearAll();
}

void WGDecodeAsModel::clearAll()
{
  for (vector<WGDecodeAsItem *>::iterator it = this->decode_as_items_.begin(); it != this->decode_as_items_.end(); ++it)
  {
    delete *it;
  }

  this->decode_as_items_.clear();
  this->changed_uint_entries_.clear();
  this->changed_string_entries_.clear();
}

void WGDecodeAsModel::fillTable()
{
  this->clearAll();

  dissector_all_tables_foreach_changed(buildChangedList, this);
}

void WGDecodeAsModel::buildChangedList(const char *table_name, ftenum_t, void *key, void *value, void *user_data)
{
  WGDecodeAsModel *model = (WGDecodeAsModel *)user_data;
  if (model == NULL)
    return;

  dissector_handle_t current_dh;
  WGDecodeAsItem *item = new WGDecodeAsItem(table_name, key);

  current_dh = dtbl_entry_get_handle((dtbl_entry_t *)value);
  item->setDissectorHandle(current_dh);

  // insert it to decode_as_items_
  model->decode_as_items_.push_back(item);
}

void WGDecodeAsModel::gatherChangedEntries(const char *table_name,
                                           ftenum_t selector_type, void *key, void *, void *user_data)
{
  WGDecodeAsModel *model = (WGDecodeAsModel *)user_data;
  if (model == NULL)
    return;

  switch (selector_type)
  {
  case FT_UINT8:
  case FT_UINT16:
  case FT_UINT24:
  case FT_UINT32:
    model->changed_uint_entries_.push_back(make_pair(table_name, GPOINTER_TO_UINT(key)));
    break;
  case FT_NONE:
    // need to reset dissector table, so this needs to be in a changed list,
    // might as well be the uint one.
    model->changed_uint_entries_.push_back(make_pair(table_name, 0));
    break;

  case FT_STRING:
  case FT_STRINGZ:
  case FT_UINT_STRING:
  case FT_STRINGZPAD:
  case FT_STRINGZTRUNC:
    model->changed_string_entries_.push_back(make_pair(table_name, (const char *)key));
    break;
  default:
    break;
  }
}

void WGDecodeAsModel::applyChanges()
{
  dissector_table_t sub_dissectors;
  module_t *module;
  pref_t *pref_value;
  dissector_handle_t handle;
  // Reset all dissector tables, then apply all rules from model.

  // We can't call g_hash_table_removed from g_hash_table_foreach, which
  // means we can't call dissector_reset_{string,uint} from
  // dissector_all_tables_foreach_changed. Collect changed entries in
  // lists and remove them separately.
  //
  // If dissector_all_tables_remove_changed existed we could call it
  // instead.
  dissector_all_tables_foreach_changed(gatherChangedEntries, this);

  for (vector<pair<const char *, uint32_t>>::iterator it = this->changed_uint_entries_.begin(); it != this->changed_uint_entries_.end(); ++it)
  {
    // Set "Decode As preferences" to default values
    sub_dissectors = find_dissector_table(it->first);
    handle = dissector_get_uint_handle(sub_dissectors, it->second);
    if (handle != NULL)
    {
      module = prefs_find_module(proto_get_protocol_filter_name(dissector_handle_get_protocol_index(handle)));
      pref_value = prefs_find_preference(module, it->first);
      if (pref_value != NULL)
      {
        module->prefs_changed_flags |= prefs_get_effect_flags(pref_value);
        reset_pref(pref_value);
      }
    }

    dissector_reset_uint(it->first, it->second);
  }

  this->changed_uint_entries_.clear();

  for (vector<pair<const char *, const char *>>::iterator it = this->changed_string_entries_.begin(); it != this->changed_string_entries_.end(); ++it)
  {
    dissector_reset_string(it->first, it->second);
  }

  this->changed_string_entries_.clear();

  for (vector<WGDecodeAsItem *>::iterator it = this->decode_as_items_.begin(); it != this->decode_as_items_.end(); ++it)
  {
    WGDecodeAsItem *item = *it;
    decode_as_t *decode_as_entry;

    if (item->currentDissector().empty())
    {
      continue;
    }

    for (GList *cur = decode_as_list; cur; cur = cur->next)
    {
      decode_as_entry = (decode_as_t *)cur->data;

      if (!g_strcmp0(decode_as_entry->table_name, item->tableName()))
      {

        ftenum_t selector_type = get_dissector_table_selector_type(item->tableName());
        gconstpointer selector_value;

        switch (selector_type)
        {
        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT24:
        case FT_UINT32:
          selector_value = GUINT_TO_POINTER(item->selectorUint());
          break;
        case FT_STRING:
        case FT_STRINGZ:
        case FT_UINT_STRING:
        case FT_STRINGZPAD:
        case FT_STRINGZTRUNC:
          selector_value = item->selectorString().c_str();
          break;
        case FT_GUID:
        case FT_NONE:
          // selector value is ignored, but dissector table needs to happen
          selector_value = NULL;
          break;
        default:
          continue;
        }

        if ((item->currentDissector() == item->defaultDissector()))
        {
          decode_as_entry->reset_value(decode_as_entry->table_name, selector_value);
          sub_dissectors = find_dissector_table(decode_as_entry->table_name);

          /* For now, only numeric dissector tables can use preferences */
          if (IS_FT_UINT(dissector_table_get_type(sub_dissectors)))
          {
            if (item->dissectorHandle() != NULL)
            {
              module = prefs_find_module(proto_get_protocol_filter_name(dissector_handle_get_protocol_index(item->dissectorHandle())));
              pref_value = prefs_find_preference(module, decode_as_entry->table_name);
              if (pref_value != NULL)
              {
                module->prefs_changed_flags |= prefs_get_effect_flags(pref_value);
                prefs_remove_decode_as_value(pref_value, item->selectorUint(), true);
              }
            }
          }
          break;
        }
        else
        {
          decode_as_entry->change_value(decode_as_entry->table_name, selector_value, item->dissectorHandle(), item->currentDissector().c_str());
          sub_dissectors = find_dissector_table(decode_as_entry->table_name);

          /* For now, only numeric dissector tables can use preferences */
          if (item->dissectorHandle() != NULL)
          {
            if (IS_FT_UINT(dissector_table_get_type(sub_dissectors)))
            {
              module = prefs_find_module(proto_get_protocol_filter_name(dissector_handle_get_protocol_index(item->dissectorHandle())));
              pref_value = prefs_find_preference(module, decode_as_entry->table_name);
              if (pref_value != NULL)
              {
                module->prefs_changed_flags |= prefs_get_effect_flags(pref_value);
                prefs_add_decode_as_value(pref_value, item->selectorUint(), false);
              }
            }
          }
          break;
        }
      }
    }
  }
  prefs_apply_all();
}

int WGDecodeAsModel::rowCount() const
{
  return decode_as_items_.size();
}

bool WGDecodeAsModel::insertRows(int row, int count)
{
  // support insertion of just one item for now.
  if (count != 1 || row < 0 || row > decode_as_items_.size())
    return false;

  WGDecodeAsItem *item = nullptr;
  const decode_as_t *firstEntry = nullptr;

  if (cap_file_ && cap_file_->edt)
  {
    // Populate the new Decode As item with the last protocol layer
    // that can support Decode As and has a selector field for that
    // present in the frame.
    //
    // XXX: This treats 0 (for UInts) and empty strings the same as
    // the fields for the tables not being present at all.

    wmem_list_frame_t *protos = wmem_list_tail(cap_file_->edt->pi.layers);
    int8_t curr_layer_num_saved = cap_file_->edt->pi.curr_layer_num;
    uint8_t curr_layer_num = wmem_list_count(cap_file_->edt->pi.layers);

    while (protos != NULL && item == nullptr)
    {
      int proto_id = GPOINTER_TO_INT(wmem_list_frame_data(protos));
      const char *proto_name = proto_get_protocol_filter_name(proto_id);
      for (GList *cur = decode_as_list; cur; cur = cur->next)
      {
        decode_as_t *entry = (decode_as_t *)cur->data;
        if (g_strcmp0(proto_name, entry->name) == 0)
        {
          if (firstEntry == nullptr)
          {
            firstEntry = entry;
          }
          ftenum_t selector_type = get_dissector_table_selector_type(entry->table_name);
          // Pick the first value in the packet for the current
          // layer for the table
          // XXX: What if the Decode As table supports multiple
          // values, but the first possible one is 0/NULL?
          cap_file_->edt->pi.curr_layer_num = curr_layer_num;
          void *selector = entry->values[0].build_values[0](&cap_file_->edt->pi);
          // FT_NONE tables don't need a value
          if (selector != NULL || selector_type == FT_NONE)
          {
            item = new WGDecodeAsItem(entry, selector);
            break;
          }
        }
      }
      protos = wmem_list_frame_prev(protos);
      curr_layer_num--;
    }

    cap_file_->edt->pi.curr_layer_num = curr_layer_num_saved;
  }

  // If we didn't find an entry with a valid selector, create an entry
  // from the last table with an empty selector, or an empty entry.
  if (item == nullptr)
  {
    item = new WGDecodeAsItem(firstEntry);
  }

  decode_as_items_.push_back(item);

  return true;
}

vector<UIDecodeAsItem> WGDecodeAsModel::getUIModel()
{
  vector<UIDecodeAsItem> res;
  for (WGDecodeAsItem *item : decode_as_items_)
  {
    res.push_back(item->data());
  }
  return res;
}