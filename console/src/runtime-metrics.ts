import type { Schema } from "./api.ts";

export const runtimeMetrics = {
  VM_CPU_CORES: {
    label: "CPU 消耗核数",
    description:
      "最近两分钟的平均 CPU 消耗，单位为核；这是用量，不是利用率百分比。",
  },
  VM_CPU_THROTTLED_PERIODS_PER_SECOND: {
    label: "CPU 限流周期速率",
    description:
      "当前运行时自身 CPU 配额发生限流的周期数/秒；不包含上级配额的限流。",
  },
  VM_CPU_THROTTLED_SECONDS_PER_SECOND: {
    label: "CPU 限流时间速率",
    description:
      "当前运行时自身 CPU 配额的累计限流秒数/秒，可能大于 1；不是 CPU 利用率，也不包含上级配额的限流。",
  },
  VM_MEMORY_BYTES: {
    label: "内存总用量",
    description:
      "宿主侧运行时的当前内存用量，包含缓存；不能直接当作应用必需内存。",
  },
  VM_MEMORY_ANON_BYTES: {
    label: "匿名内存用量",
    description: "宿主侧运行时的匿名内存；与文件内存相加不等于内存总用量。",
  },
  VM_MEMORY_FILE_BYTES: {
    label: "文件内存用量",
    description: "文件内存包含缓存、临时文件系统和共享内存，并非全部可回收。",
  },
  VM_MEMORY_OOM_EVENTS_PER_SECOND: {
    label: "内存不足事件速率",
    description:
      "宿主侧运行时发生内存不足事件的次数/秒；不等于进程被终止次数。",
  },
  VM_MEMORY_OOM_KILLS_PER_SECOND: {
    label: "内存不足终止进程速率",
    description: "宿主侧运行时因内存不足被终止的进程数/秒；不代表实例被终止。",
  },
  VM_IO_READ_BYTES_PER_SECOND: {
    label: "块设备读取速率",
    description:
      "宿主侧运行时各块设备读取字节数/秒，不代表客户机应用的有效吞吐。",
  },
  VM_IO_WRITE_BYTES_PER_SECOND: {
    label: "块设备写入速率",
    description:
      "宿主侧运行时各块设备写入字节数/秒，不代表客户机应用的有效吞吐。",
  },
  VM_TASKS: {
    label: "宿主运行时任务数",
    description: "宿主侧运行时的线程和任务数量，不是客户机内的进程数。",
  },
} satisfies Record<
  Schema["RuntimeMetric"],
  { label: string; description: string }
>;

export const runtimeMetricUnits = {
  cores: "核",
  bytes: "字节",
  bytes_per_second: "字节/秒",
  tasks: "任务",
  periods_per_second: "周期/秒",
  seconds_per_second: "秒/秒",
  events_per_second: "次/秒",
} satisfies Record<Schema["MetricSeries"]["unit"], string>;
