<template>
  <v-file-input label="File input" @change="fileChangeHandler"></v-file-input>
  <v-text-field
    v-model:value="filter_input"
    placeholder="display filter, example: tcp"
  />
  <v-data-table-virtual
    :headers="columns"
    :items="tableData"
    :sticky="true"
    :height="400"
    density="compact"
    hover
    @row-click="rowClickHandler"
    @row-contextmenu="rowContextmenuHandler"
  >
    <!-- 使用默认插槽自定义行 -->
    <template #item="{ item }">
      <tr
        @contextmenu.prevent="rowContextmenuHandler($event, item)"
        :style="getRowProps(item)"
      >
        <td v-for="column in columns" :key="column.key">
          {{ item[column.key] }}
        </td>
      </tr>
    </template>
  </v-data-table-virtual>
  <!-- 数据包详情 -->
  <div
    v-if="selectedPacket?.tree?.length"
    class="flex flex-row h-full w-full mt-2"
  >
    <div class="w-full overflow-auto">
      <DissectionTree
        id="root"
        class="w-full"
        :tree="selectedPacket.tree"
        :selected="selectedTreeEntry.id"
        :select="setSelectedTreeEntry"
        :set-filter="setFilter"
      />
    </div>
    <div class="raw-data-container w-full overflow-auto">
      <div
        v-for="(data_source, idx) in selectedPacket.data_sources"
        :key="data_source.idx"
        class="mx-2"
      >
        <DissectionDump
          :buffer="Buffer.from(data_source.data, 'base64')"
          :selected="
            idx === selectedTreeEntry.idx
              ? [selectedTreeEntry.start, selectedTreeEntry.length]
              : [0, 0]
          "
          @select="onDataSourceSelect(idx, $event)"
        />
      </div>
    </div>
  </div>
  <!-- 添加右键菜单 -->
  <div
    v-show="contextMenu.show"
    class="fixed z-[9999] bg-white shadow-md rounded py-1 min-w-[120px]"
    :style="{
      left: contextMenu.x + 'px',
      top: contextMenu.y + 'px',
    }"
  >
    <div
      class="px-3 py-1.5 hover:bg-light-200 cursor-pointer"
      @click="handleTraceFlow"
    >
      {{ "追踪流" }}
    </div>
  </div>
  <!-- 追踪流 -->
  <v-dialog
    v-model="showTraceFlowDialog"
    width="950px"
    :with-footer="false"
    :title="'追踪流'"
  >
    <div class="p-5 text-sm bg-white overflow-auto">
      <div v-if="streamedData.length" class="relative">
        <div
          v-for="(data, index) in streamedData"
          :key="index"
          :class="data.server ? 'text-red-500' : 'text-blue-500'"
          class="whitespace-pre-wrap mb-3"
        >
          <div>{{ data.data }}</div>
        </div>
      </div>

      <div v-else class="text-sm">
        <div>
          {{ `服务器: ${followResult?.shost}:${followResult?.sport}` }}
        </div>
        <div>
          {{ `客户端: ${followResult?.chost}:${followResult?.cport}` }}
        </div>
        <div>{{ `服务器发送: ${followResult?.sbytes} 字节` }}</div>
        <div>{{ `客户端发送: ${followResult?.cbytes} 字节` }}</div>
      </div>
    </div>
  </v-dialog>
</template>

<script lang="ts" setup>
import { get, map, reduce } from "lodash-es";
import { Buffer } from "buffer";

import DissectionTree from "./DissectionTree.vue";
import DissectionDump from "./DissectionDump.vue";

import type { Follow, LoadSummary } from "@goodtools/wiregasm";
import type { TypedWorker, WorkerResponse, WorkerResponseMap } from "./types";
import {
  ref,
  computed,
  reactive,
  watchEffect,
  onMounted,
  onUnmounted,
} from "vue";
import { onClickOutside } from "@vueuse/core";

function rowClickHandler(row: any) {
  selected_row_idx.value = row.raw.number;
}
const tableData = ref<Record<string, any>[]>([]);
function getRowProps(item: Record<string, any>) {
  const raw = item.raw;
  return {
    backgroundColor: `#${Number(raw.bg).toString(16)}`,
    color: `#${Number(raw.fg).toString(16)}`,
    cursor: "pointer",
  };
}

// 类型定义
type TreeEntry = {
  id: string;
  idx: number;
  start: number;
  length: number;
};

// 状态管理
const showTraceFlowDialog = ref(false);
const status = ref<string>("加载中...");
const loading = ref(true);
const processed = ref(false);
const filter_input = ref("");
const selected_row_idx = ref(0);
const selectedPacket = ref<any>(null);
const preparedPositions = ref(new Map<number, TreeEntry>());
const NO_SELECTION: TreeEntry = { id: "", idx: 0, start: 0, length: 0 };
const selectedTreeEntry = ref<TreeEntry>(NO_SELECTION);
const summary = ref<LoadSummary>({
  packet_count: 0,
  filename: "",
  file_type: "",
  file_length: 0,
  file_encap_type: "",
  start_time: 0,
  stop_time: 0,
  elapsed_time: 0,
});

// 表格相关
const columns = ref<{ title: string; key: string }[]>([]);

// Worker 初始化
const worker = new Worker(new URL("./wireshark.worker.ts", import.meta.url), {
  type: "module",
}) as TypedWorker;

// 添加右键菜单状态
const contextMenu = reactive({
  show: false,
  x: 0,
  y: 0,
  row: null as any,
});

// 处理右键菜单显示
function rowContextmenuHandler(event: MouseEvent, row: any) {
  event.preventDefault();
  contextMenu.show = true;
  contextMenu.x = event.clientX;
  contextMenu.y = event.clientY;
  contextMenu.row = row;
}

// 处理追踪流点击
const streamedData = ref<
  {
    number: number;
    server: number;
    data: any;
  }[]
>([]);
const followResult = ref<Follow>();
function handleTraceFlow() {
  const { port1, port2 } = new MessageChannel();
  port1.onmessage = (ev) => {
    followResult.value = ev.data.followResult;
    streamedData.value = ev.data.payloads;
    filter_input.value = ev.data.filter;
  };
  worker.postMessage(
    {
      type: "follow-stream",
      number: contextMenu.row.raw.number,
    },
    [port2]
  );
  showTraceFlowDialog.value = true;
  contextMenu.show = false;
}

// 点击他区域关闭菜单
onClickOutside(ref(document.body), () => {
  contextMenu.show = false;
});

// 数据处理方法
const controller = new AbortController();
let processInterval: ReturnType<typeof setInterval> | null = null;
const fileChangeHandler = async (ev: Event) => {
  const f = (ev.target as HTMLInputElement).files?.[0];
  if (!f) return window.alert("文件不存在");
  processed.value = false;
  const buf = await f?.arrayBuffer();
  worker.postMessage(
    {
      type: "process",
      name: f.name,
      arrayBuffer: buf,
    },
    [buf]
  );
};

onUnmounted(() => {
  controller.abort("组件卸载，取消请求");
  worker.terminate();
  processInterval && clearInterval(processInterval);
});

const fetchTableData = async () => {
  loading.value = true;
  const { port1, port2 } = new MessageChannel();

  port1.onmessage = (ev) => {
    try {
      const { data } = ev.data;
      if (!data?.frames) {
        throw new Error("无效的数据格式");
      }
      const data_source = map(data.frames, (f: any) => {
        return reduce(
          columns.value,
          (acc: Record<string, any>, col: Record<string, any>, idx: any) => {
            acc[col.key] = get(f, ["columns", idx]);
            return acc;
          },
          { raw: f }
        );
      });
      tableData.value = data_source;
    } catch (error) {
      status.value =
        "处理表格数据失败: " +
        (error instanceof Error ? error.message : "未知错误");
    } finally {
      port1.close();
      port2.close();
      loading.value = false;
    }
  };

  try {
    worker.postMessage(
      {
        type: "select-frames",
        skip: 0,
        limit: 0,
        filter: filter_input.value,
      },
      [port2]
    );
  } catch (error) {
    loading.value = false;
  }
};

const init = ref(false);
// Worker 消息处理策略
const MESSAGE_STRATEGIES: {
  [K in keyof WorkerResponseMap]: (
    ev: MessageEvent<WorkerResponseMap[K]>
  ) => void;
} = {
  init: () => {
    loading.value = false;
    worker.postMessage({ type: "columns" });
    init.value = true;
  },
  columned: (ev) => {
    columns.value = map(ev.data.columns, (c) => ({
      title: c,
      key: c,
    }));
  },
  status: (ev) => {
    status.value = ev.data.status;
  },
  processed: (ev) => {
    const { summary: _summary } = ev.data;
    summary.value = _summary.summary;
    processed.value = true;
    fetchTableData();
    if (selected_row_idx.value === 0) {
      selected_row_idx.value = 1;
    }
  },
  selected: (ev) => {
    preparedPositions.value = new Map(preparePositions("root", ev.data));
    selectedPacket.value = ev.data;
  },
  error: (ev) => {
    status.value = `错误: ${ev.data.error}`;
    loading.value = false;
  },
};

// 工具方法
function preparePositions(id: string, node: any): Map<any, any> {
  let map = new Map();
  if (node.tree?.length > 0) {
    for (let i = 0; i < node.tree.length; i++) {
      map = new Map([...map, ...preparePositions(`${id}-${i}`, node.tree[i])]);
    }
  } else if (node.length > 0) {
    map.set(id, {
      id,
      idx: node.data_source_idx,
      start: node.start,
      length: node.length,
    });
  }
  return map;
}

// 事件监听和响应
worker.addEventListener(
  "message",
  (ev: MessageEvent<WorkerResponse<keyof WorkerResponseMap>>) => {
    const type = ev.data.type;
    MESSAGE_STRATEGIES[type]?.(ev as any);
  }
);

// 监听效果
watchEffect(() => {
  const header = columns.value.map((c) => ({
    id: c.title,
    accessorKey: c.title,
  }));
});

watchEffect(() => {
  if (!processed.value) return;
  worker.postMessage({
    type: "select",
    number: selected_row_idx.value,
  });
});

watchEffect(() => {
  if (!processed.value) return;
  const { port1, port2 } = new MessageChannel();
  port1.onmessage = (ev) => {
    if (ev.data.result === true) fetchTableData();
  };
  worker.postMessage({ type: "check-filter", filter: filter_input.value }, [
    port2,
  ]);
});

// 交互处理方法
function setSelectedTreeEntry(entry: TreeEntry) {
  selectedTreeEntry.value = entry || NO_SELECTION;
}

function setFilter(filter: string) {
  filter_input.value = filter;
}

function onDataSourceSelect(src_idx: number, pos: number) {
  // find the smallest one
  let current: number | null = null;

  for (const [k, pp] of preparedPositions.value) {
    if (pp.idx !== src_idx) continue;

    if (pos >= pp.start && pos <= pp.start + pp.length) {
      if (
        current !== null &&
        preparedPositions.value.get(current)!.length > pp.length
      ) {
        current = k;
      } else {
        current = k;
      }
    }
  }

  if (current !== null) {
    setSelectedTreeEntry(preparedPositions.value.get(current)!);
  }
}
</script>
