// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-2020 Datadog, Inc.

package tag

import (
	"sort"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestProviderExpectedTags(t *testing.T) {
	mockConfig := config.Mock()

	tags := []string{"tag1:value1", "tag2", "tag3"}

	mockConfig.Set("tags", tags)
	// Setting a test-friendly value for the deadline
	mockConfig.Set("logs_config.expected_tags_duration", "5s")
	defer mockConfig.Set("tags", nil)
	defer mockConfig.Set("expected_tags_duration", 0)

	p := NewProvider("foo")
	pp := p.(*provider)

	// Is provider expected?
	d := mockConfig.GetDuration("logs_config.expected_tags_duration")
	assert.InDelta(t, time.Now().Add(d).Unix(), pp.expectedTagsDeadline.Unix(), 1)
	assert.True(t, pp.submitExpectedTags)

	tt := pp.GetTags()
	sort.Strings(tags)
	sort.Strings(tt)
	assert.Equal(t, tags, tt)

	// let the deadline expire + a little grace period
	<-time.After(time.Until(pp.expectedTagsDeadline.Add(2 * time.Second)))

	pp.Lock()
	assert.False(t, pp.submitExpectedTags)
	pp.Unlock()
	assert.Equal(t, []string{}, pp.GetTags())

}
