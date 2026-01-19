package base

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

func TestStatusUpdater(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))

	t.Run("UpdateStatus succeeds", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-gateway",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{
					{
						Name:     "http",
						Port:     80,
						Protocol: avapigwv1alpha1.ProtocolHTTP,
					},
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gateway).
			WithStatusSubresource(gateway).
			Build()

		updater := NewStatusUpdater(client)

		// Update status
		gateway.Status.Phase = avapigwv1alpha1.PhaseStatusReady
		err := updater.UpdateStatus(context.Background(), gateway)
		require.NoError(t, err)
	})

	t.Run("WithMaxRetries sets max retries", func(t *testing.T) {
		client := fake.NewClientBuilder().WithScheme(scheme).Build()
		updater := NewStatusUpdater(client).WithMaxRetries(5)

		assert.Equal(t, 5, updater.maxRetries)
	})
}

func TestUpdateStatusWithRetry(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))

	t.Run("UpdateStatusWithRetry succeeds", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-gateway",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{
					{
						Name:     "http",
						Port:     80,
						Protocol: avapigwv1alpha1.ProtocolHTTP,
					},
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gateway).
			WithStatusSubresource(gateway).
			Build()

		err := UpdateStatusWithRetry(context.Background(), client, gateway, func(obj *avapigwv1alpha1.Gateway) error {
			obj.Status.Phase = avapigwv1alpha1.PhaseStatusReady
			return nil
		}, 3)
		require.NoError(t, err)
	})

	t.Run("UpdateStatusWithRetry uses default retries when zero", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-gateway",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{
					{
						Name:     "http",
						Port:     80,
						Protocol: avapigwv1alpha1.ProtocolHTTP,
					},
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gateway).
			WithStatusSubresource(gateway).
			Build()

		err := UpdateStatusWithRetry(context.Background(), client, gateway, func(obj *avapigwv1alpha1.Gateway) error {
			obj.Status.Phase = avapigwv1alpha1.PhaseStatusReady
			return nil
		}, 0)
		require.NoError(t, err)
	})

	t.Run("UpdateStatusWithRetry uses default retries when negative", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-gateway",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{
					{
						Name:     "http",
						Port:     80,
						Protocol: avapigwv1alpha1.ProtocolHTTP,
					},
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gateway).
			WithStatusSubresource(gateway).
			Build()

		err := UpdateStatusWithRetry(context.Background(), client, gateway, func(obj *avapigwv1alpha1.Gateway) error {
			obj.Status.Phase = avapigwv1alpha1.PhaseStatusReady
			return nil
		}, -1)
		require.NoError(t, err)
	})

	t.Run("UpdateStatusWithRetry returns error from update function", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-gateway",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{
					{
						Name:     "http",
						Port:     80,
						Protocol: avapigwv1alpha1.ProtocolHTTP,
					},
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gateway).
			WithStatusSubresource(gateway).
			Build()

		expectedErr := assert.AnError
		err := UpdateStatusWithRetry(context.Background(), client, gateway, func(obj *avapigwv1alpha1.Gateway) error {
			return expectedErr
		}, 3)
		require.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})

	t.Run("UpdateStatusWithRetry handles non-existent object", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "non-existent-gateway",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{
					{
						Name:     "http",
						Port:     80,
						Protocol: avapigwv1alpha1.ProtocolHTTP,
					},
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&avapigwv1alpha1.Gateway{}).
			Build()

		err := UpdateStatusWithRetry(context.Background(), client, gateway, func(obj *avapigwv1alpha1.Gateway) error {
			obj.Status.Phase = avapigwv1alpha1.PhaseStatusReady
			return nil
		}, 3)
		require.Error(t, err)
	})
}

func TestStatusUpdater_UpdateStatus_Errors(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))

	t.Run("UpdateStatus handles non-existent object", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "non-existent-gateway",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{
					{
						Name:     "http",
						Port:     80,
						Protocol: avapigwv1alpha1.ProtocolHTTP,
					},
				},
			},
		}

		client := fake.NewClientBuilder().
			WithScheme(scheme).
			WithStatusSubresource(&avapigwv1alpha1.Gateway{}).
			Build()

		updater := NewStatusUpdater(client)
		gateway.Status.Phase = avapigwv1alpha1.PhaseStatusReady
		err := updater.UpdateStatus(context.Background(), gateway)
		require.Error(t, err)
	})
}
