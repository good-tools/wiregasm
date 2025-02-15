import { Buffer } from 'buffer'

import pako from 'pako'
// @ts-ignore
import wasmModuleCompressed from '@goodtools/wiregasm/dist/wiregasm.wasm.gz?url'
// @ts-ignore
import wasmDataCompressed from '@goodtools/wiregasm/dist/wiregasm.data.gz?url'
// @ts-ignore
import loadWiregasm from '@goodtools/wiregasm/dist/wiregasm'
import { Wiregasm, vectorToArray } from '@goodtools/wiregasm'

import type { WorkerMessageMap, WorkerResponseMap } from './types'

const wg = new Wiregasm()

function replacer(_: string, value: any) {
  if (value.constructor.name.startsWith('Vector')) {
    return vectorToArray(value)
  }
  return value
}

const inflateRemoteBuffer = async (url: string) => {
  const res = await fetch(url)
  const buf = await res.arrayBuffer()
  try {
    return pako.inflate(buf).buffer
  } catch (err) {
    return buf
  }
}

const fetchPackages = async () => {
  const [wasm, data] = await Promise.all([
    await inflateRemoteBuffer(wasmModuleCompressed),
    await inflateRemoteBuffer(wasmDataCompressed)
  ])

  return { wasm, data }
}
let WASM: ArrayBuffer
let DATA: ArrayBuffer
fetchPackages().then(({ wasm, data }) => {
  WASM = wasm
  DATA = data
  init(WASM, DATA)
})

async function init(wasm: ArrayBuffer, data: ArrayBuffer) {
  try {
    await wg.init(loadWiregasm, {
      wasmBinary: wasm,
      getPreloadedPackage() {
        return data
      },
      handleStatus: (type, status) =>
        postMessage({
          type: 'status',
          status,
          code: type
        })
    })
    postMessage({ type: 'init' })
  } catch (e) {
    postMessage({ type: 'error', error: e })
  }
}

const MESSAGE_STRATEGIES: {
  [K in keyof WorkerMessageMap]: (ev: MessageEvent<{ type: K } & WorkerMessageMap[K]>) => void
} = {
  columns: _ev => {
    postMessage<'columned'>({
      type: 'columned',
      columns: wg.columns()
    })
  },
  select: ev => {
    const number = ev.data.number
    const res = wg.frame(number)
    const temp = JSON.parse(JSON.stringify(res, replacer))
    postMessage<'selected'>({
      type: 'selected',
      tree: temp.tree,
      data_sources: temp.data_sources
    })
  },
  'select-frames': ev => {
    const filter = ev.data.filter
    const res = wg.frames(filter, 0, 0)
    ev.ports[0].postMessage({
      data: JSON.parse(JSON.stringify(res, replacer))
    })
  },
  'check-filter': ev => {
    const filter = ev.data.filter || ''
    const res = wg.lib.checkFilter(filter)
    if (res.ok) {
      ev.ports[0].postMessage({ result: true })
    } else {
      ev.ports[0].postMessage({ error: res.error })
    }
  },
  process: async ev => {
    const name = ev.data.name
    const data = ev.data.arrayBuffer

    try {
      // 数据验证
      if (!data || data.byteLength === 0) {
        throw new Error('无效的数据缓冲区')
      }

      // 重置 Wiregasm 状态
      await init(WASM, DATA)

      // 创建新的 Buffer 并确保数据完整性
      const buffer = Buffer.from(new Uint8Array(data))
      if (buffer.length !== data.byteLength) {
        throw new Error('数据转换失败')
      }

      const res = wg.load(name, buffer)

      postMessage<'processed'>({
        type: 'processed',
        summary: res,
        name
      })
    } catch (error) {
      postMessage<'error'>({
        type: 'error',
        error: error instanceof Error ? error.message : '未知错误'
      })
    }
  },
  'follow-stream': ev => {
    const number = ev.data.number
    const res = wg.frame(number)
    const temp = JSON.parse(JSON.stringify(res, replacer))
    const result = wg.follow(temp.follow[0][0], temp.follow[0][1])
    // 如果需要转换成数组
    const payloadsArray = []
    for (let i = 0; i < result.payloads.size(); i++) {
      const payload = result.payloads.get(i)
      const decoded = atob(payload.data).trim()
      payloadsArray.push({
        ...payload,
        data: decoded
      })
    }
    ev.ports[0].postMessage({
      type: 'streamed',
      payloads: payloadsArray,
      followResult: result,
      filter: temp.follow[0][1]
    })
  }
}

// 类型安全的 postMessage
function postMessage<K extends keyof WorkerResponseMap>(
  message: { type: K } & WorkerResponseMap[K]
): void {
  self.postMessage(message)
}

// 类型安全的消息处理
self.onmessage = (
  event: MessageEvent<{ type: keyof WorkerMessageMap } & WorkerMessageMap[keyof WorkerMessageMap]>
) => {
  const type = event.data.type as keyof WorkerMessageMap
  MESSAGE_STRATEGIES[type](event as any)
}
