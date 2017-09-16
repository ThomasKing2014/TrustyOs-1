/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <trusty_app_manifest.h>
#include <stddef.h>
#include <stdio.h>

/* {48c32cae-974d-4597-88d7-bcfccdb2c803} */
#define SDK_FAKE_LIB_UUID \
	{ 0x48c32cae, 0x974d, 0x4597, \
	  { 0x88, 0xd7, 0xbc, 0xfc, 0xcd, 0xb2, 0xc8, 0x03 } }

trusty_app_manifest_t TRUSTY_APP_MANIFEST_ATTRS trusty_app_manifest =
{
	.uuid = SDK_FAKE_LIB_UUID,

	/* optional configuration options here */
	{
		TRUSTY_APP_CONFIG_MIN_HEAP_SIZE(4096),

		TRUSTY_APP_CONFIG_MIN_STACK_SIZE(4096),
	},
};

