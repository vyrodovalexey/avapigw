package base

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestFinalizerHandler(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	const finalizerName = "test.example.com/finalizer"

	t.Run("HasFinalizer returns false when finalizer not present", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(scheme).Build()
		handler := NewFinalizerHandler(client, finalizerName)

		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cm",
				Namespace: "default",
			},
		}

		assert.False(t, handler.HasFinalizer(cm))
	})

	t.Run("HasFinalizer returns true when finalizer present", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(scheme).Build()
		handler := NewFinalizerHandler(client, finalizerName)

		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-cm",
				Namespace:  "default",
				Finalizers: []string{finalizerName},
			},
		}

		assert.True(t, handler.HasFinalizer(cm))
	})

	t.Run("EnsureFinalizer adds finalizer when not present", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cm",
				Namespace: "default",
			},
		}
		client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm).Build()
		handler := NewFinalizerHandler(client, finalizerName)

		added, err := handler.EnsureFinalizer(context.Background(), cm)
		require.NoError(t, err)
		assert.True(t, added)
		assert.True(t, handler.HasFinalizer(cm))
	})

	t.Run("EnsureFinalizer returns false when finalizer already present", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-cm",
				Namespace:  "default",
				Finalizers: []string{finalizerName},
			},
		}
		client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm).Build()
		handler := NewFinalizerHandler(client, finalizerName)

		added, err := handler.EnsureFinalizer(context.Background(), cm)
		require.NoError(t, err)
		assert.False(t, added)
	})

	t.Run("RemoveFinalizer removes finalizer when present", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-cm",
				Namespace:  "default",
				Finalizers: []string{finalizerName},
			},
		}
		client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm).Build()
		handler := NewFinalizerHandler(client, finalizerName)

		removed, err := handler.RemoveFinalizer(context.Background(), cm)
		require.NoError(t, err)
		assert.True(t, removed)
		assert.False(t, handler.HasFinalizer(cm))
	})

	t.Run("RemoveFinalizer returns false when finalizer not present", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cm",
				Namespace: "default",
			},
		}
		client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm).Build()
		handler := NewFinalizerHandler(client, finalizerName)

		removed, err := handler.RemoveFinalizer(context.Background(), cm)
		require.NoError(t, err)
		assert.False(t, removed)
	})

	t.Run("FinalizerName returns the finalizer name", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(scheme).Build()
		handler := NewFinalizerHandler(client, finalizerName)

		assert.Equal(t, finalizerName, handler.FinalizerName())
	})
}

func TestConvenienceFunctions(t *testing.T) {
	const finalizerName = "test.example.com/finalizer"

	t.Run("ContainsFinalizer", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-cm",
				Namespace:  "default",
				Finalizers: []string{finalizerName},
			},
		}

		assert.True(t, ContainsFinalizer(cm, finalizerName))
		assert.False(t, ContainsFinalizer(cm, "other-finalizer"))
	})

	t.Run("AddFinalizer", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cm",
				Namespace: "default",
			},
		}

		AddFinalizer(cm, finalizerName)
		assert.Contains(t, cm.GetFinalizers(), finalizerName)
	})

	t.Run("RemoveFinalizerFromObject", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:       "test-cm",
				Namespace:  "default",
				Finalizers: []string{finalizerName},
			},
		}

		RemoveFinalizerFromObject(cm, finalizerName)
		assert.NotContains(t, cm.GetFinalizers(), finalizerName)
	})
}
