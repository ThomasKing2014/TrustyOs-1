/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stddef.h>
#include <trusty_app_manifest.h>

trusty_app_manifest_t TRUSTY_APP_MANIFEST_ATTRS trusty_app_manifest =
{
    /* UUID : {32305457-0001-0002-536563426F6F7400} */
    { 0x32305457, 0x0001, 0x0002,
    { 0x53, 0x65, 0x63, 0x42, 0x6f, 0x6f, 0x74, 0x00 } },

    /* optional configuration options here */
    {
        TRUSTY_APP_CONFIG_MIN_HEAP_SIZE(2 * 4096),
        TRUSTY_APP_CONFIG_MIN_STACK_SIZE(1 * 4096),
    },
};
