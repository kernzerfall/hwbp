# SPDX-License-Identifier: EUPL-1.2

# JNI entry point implemented in Rust (Java_k3r_hwbp_core_NativeCore_invoke).
-keep class k3r.hwbp.core.NativeCore { native <methods>; }

# protobuf-lite resolves message fields by name via reflection (e.g. `op_`).
-keep class * extends com.google.protobuf.GeneratedMessageLite { <fields>; }
