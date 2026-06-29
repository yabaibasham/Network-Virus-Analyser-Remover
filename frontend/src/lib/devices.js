import {
  Server,
  Laptop,
  MonitorSmartphone,
  Smartphone,
  Camera,
  Car,
  Cpu,
  Router,
  HardDrive,
  Activity,
} from "lucide-react";

export const DEVICE_META = {
  linux_server:    { label: "LINUX SRV",  Icon: Server },
  windows_pc:      { label: "WIN PC",     Icon: MonitorSmartphone },
  macbook:         { label: "MACBOOK",    Icon: Laptop },
  android:         { label: "ANDROID",    Icon: Smartphone },
  iphone:          { label: "IPHONE",     Icon: Smartphone },
  ip_camera:       { label: "IP CAM",     Icon: Camera },
  tesla_vehicle:   { label: "TESLA",      Icon: Car },
  iot_sensor:      { label: "IOT",        Icon: Activity },
  router:          { label: "ROUTER",     Icon: Router },
  raspberry_pi:    { label: "RPI",        Icon: Cpu },
};

export function deviceIcon(type) {
  return (DEVICE_META[type] || { Icon: HardDrive }).Icon;
}

export const STATUS_STYLES = {
  clean:       { color: "#0044FF", label: "CLEAN" },
  scanning:    { color: "#FFCC00", label: "SCANNING" },
  infected:    { color: "#FF3B30", label: "INFECTED" },
  quarantined: { color: "#888888", label: "QUARANTINED" },
  offline:     { color: "#444444", label: "OFFLINE" },
};
