package main

import (
	"context"
	"errors"
	"testing"
)

func TestDevPrepAdmissionSnapshotsPendingCategoryUntilPreparationFinishes(t *testing.T) {
	var a builderDevPrepAdmission
	ctx := context.Background()
	const first = "op_11111111111111111111111111111111"
	const next = "op_22222222222222222222222222222222"
	emptyScan := func(context.Context, map[string]builderCategory) (builderCategorySet, error) {
		return builderCategorySet{}, nil
	}
	firstStart := func(_ context.Context, _ string, excluded *builderCategorySet) (builderCategory, error) {
		if *excluded != (builderCategorySet{}) {
			t.Fatalf("unexpected exclusions on first START: %v", excluded)
		}
		return 1, nil
	}
	if _, err := a.startBuilder(ctx, first, emptyScan, firstStart); err != nil {
		t.Fatal(err)
	}

	// Simulate preparation finishing after the next START has taken its
	// pending snapshot. Even if the disk scan saw no tree, that snapshot
	// must retain the category all the way to the manager allocator.
	finishDuringScan := func(_ context.Context, pending map[string]builderCategory) (builderCategorySet, error) {
		a.finishPreparation(first)
		if got := pending[first]; got != 1 {
			t.Fatalf("pending snapshot = %v; want c1", got)
		}
		return builderCategorySet{}, nil
	}
	manager := newBuilderManager(0, 0)
	category, err := a.startBuilder(ctx, next, finishDuringScan, func(_ context.Context, _ string, excluded *builderCategorySet) (builderCategory, error) {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		got, ok := manager.allocateCategoryLocked(*excluded)
		if !ok {
			t.Fatal("manager pool unexpectedly exhausted")
		}
		return got, nil
	})
	if err != nil || category != 2 {
		t.Fatalf("second START = %v, %v; want c2", category, err)
	}
	a.finishPreparation(next)
	if _, err := a.startBuilder(ctx, first, emptyScan, firstStart); err != nil {
		t.Fatal(err)
	}
}

func TestDevPrepAdmissionRefusesUnreadableCategoriesBeforeStart(t *testing.T) {
	var a builderDevPrepAdmission
	scanErr := errors.New("cannot read prepared tree")
	scan := func(context.Context, map[string]builderCategory) (builderCategorySet, error) {
		return builderCategorySet{}, scanErr
	}
	start := func(context.Context, string, *builderCategorySet) (builderCategory, error) {
		t.Fatal("manager START ran after a failed scan")
		return 0, nil
	}
	if _, err := a.startBuilder(context.Background(), "op_11111111111111111111111111111111", scan, start); !errors.Is(err, scanErr) {
		t.Fatalf("START error = %v; want scan failure", err)
	}
}
