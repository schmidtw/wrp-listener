/**
 * Copyright 2019 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package webhookClient

import (
	"net/http"

	"github.com/stretchr/testify/mock"
)

type MockAcquirer struct {
	mock.Mock
}

func (a *MockAcquirer) Acquire() (string, error) {
	args := a.Called()
	return args.String(0), args.Error(1)
}

type MockRoundTripper struct {
	mock.Mock
}

func (rt *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	args := rt.Called(req)
	return args.Get(0).(*http.Response), args.Error(1)
}

type mockSecretGetter struct {
	mock.Mock
}

func (sg *mockSecretGetter) GetSecret() (string, error) {
	args := sg.Called()
	return args.String(0), args.Error(1)
}
