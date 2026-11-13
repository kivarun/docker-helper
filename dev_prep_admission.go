package main

import (
	"context"
	"fmt"
	"maps"
	"sync"
)

// builderDevPrepAdmission bridges the interval between START and the end of
// preparation. A builder can exit during that interval, so even a new
// manager with an empty instance map must honor the pending category.
type builderDevPrepAdmission struct {
	once  sync.Once
	start chan struct{}

	mu      sync.Mutex
	pending map[string]builderCategory
}

// startBuilder serializes the exclusion snapshot and START until the
// returned category is recorded. Preparation and buildctl can run in
// parallel across operations.
func (a *builderDevPrepAdmission) startBuilder(
	ctx context.Context, opID string,
	scan func(context.Context, map[string]builderCategory) (builderCategorySet, error),
	start func(context.Context, string, *builderCategorySet) (builderCategory, error),
) (builderCategory, error) {
	a.once.Do(func() {
		a.start = make(chan struct{}, 1)
	})
	select {
	case a.start <- struct{}{}:
		defer func() { <-a.start }()
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	a.mu.Lock()
	pending := maps.Clone(a.pending)
	a.mu.Unlock()

	excluded, err := scan(ctx, pending)
	if err != nil {
		return 0, fmt.Errorf("inspect prepared-tree categories: %w", err)
	}
	for _, category := range pending {
		excluded.add(category)
	}
	category, err := start(ctx, opID, &excluded)
	if err != nil {
		return 0, err
	}
	a.mu.Lock()
	if a.pending == nil {
		a.pending = make(map[string]builderCategory)
	}
	a.pending[opID] = category
	a.mu.Unlock()
	return category, nil
}

// finishPreparation drops the pending hold once the preparer has returned
// or the driver has decided to skip it. Any surviving tree is then visible
// to the disk scan. A snapshot taken earlier already holds its category.
func (a *builderDevPrepAdmission) finishPreparation(opID string) {
	a.mu.Lock()
	delete(a.pending, opID)
	a.mu.Unlock()
}
