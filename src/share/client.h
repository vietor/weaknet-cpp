#pragma once

enum RuningStep {
  STEP_INIT = 0,
  STEP_WAITHDR,
  STEP_CONNECT,
  STEP_TRANSPORT,
  STEP_TERMINATE
};
