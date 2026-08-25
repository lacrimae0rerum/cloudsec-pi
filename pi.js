import { Type, StringEnum } from "@earendil-works/pi-ai";
import { BorderedLoader, DynamicBorder, getSettingsListTheme } from "@earendil-works/pi-coding-agent";
import { Container, SelectList, SettingsList, Text } from "@earendil-works/pi-tui";
import { createControlUi } from "./lib/control-center.js";
import { registerCloudsec } from "./index.js";

export default function cloudsecPi(pi) {
  const controlUi = createControlUi({
    BorderedLoader,
    Container,
    DynamicBorder,
    SelectList,
    SettingsList,
    Text,
    getSettingsListTheme,
  });
  registerCloudsec(pi, { Type, StringEnum }, { controlUi });
}
