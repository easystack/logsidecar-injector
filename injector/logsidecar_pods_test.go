package injector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"text/template"

	evanjsonpatch "github.com/evanphx/json-patch"
	"github.com/stretchr/testify/assert"
	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestLogsidecarPodMutate(t *testing.T) {
	filebeatConfig := `
filebeat.inputs:
  - type: log
    enabled: true
    paths:
    {{range .Paths}}
    - {{.}}
    {{end}}
output.console:
  codec.format:
    string: '%{[message]}'
logging.level: warning
`
	tmpl, err := template.New("filebeat.yaml").Parse(filebeatConfig)
	if err != nil {
		t.Fatal(err)
	}
	previousConfig := injectorConfig
	injectorConfig = &InjectorConfig{FilebeatConfigTemplate: tmpl}
	defer func() { injectorConfig = previousConfig }()

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				logsidecarAnnotationName: "{\"containerLogConfigs\": {\"app-container\": {\"datavolume\": [\"log/*.log\"]}}}",
			},
		},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{
				Name:         "datavolume",
				VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
			}},
			Containers: []corev1.Container{{
				Name:    "app-container",
				Image:   "alpine",
				Command: []string{"/bin/sh"},
				Args:    []string{"-c", "while true; do date >> /data/log/app-test.log; sleep 30; done"},
				VolumeMounts: []corev1.VolumeMount{{
					Name:      "datavolume",
					MountPath: "/data",
				}},
			}},
		},
	}

	mutatedPod := pod.DeepCopy()
	lscConfig, err := decodeLogsidecarConfig(mutatedPod.Annotations[logsidecarAnnotationName])
	if err != nil {
		t.Fatal(err)
	}
	added, err := addLogsidecarPart(&mutatedPod.Spec, lscConfig, "")
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, added)

	var buffer bytes.Buffer
	if err := injectorConfig.FilebeatConfigTemplate.Execute(&buffer, struct {
		Paths []string
	}{[]string{filepath.Clean("/container-app-container/data/log/*.log")}}); err != nil {
		t.Fatal(err)
	}
	fbConfigEcho := JoinLines(buffer.String(), "echo \"",
		fmt.Sprintf("\" >> %s/%s ; ", logsidecarConfigDir, filebeatConfigFileName))

	expectedPod := pod.DeepCopy()
	expectedPod.Spec.InitContainers = []corev1.Container{{
		Name:            logsidecarInitContainerName,
		Image:           injectorConfig.SidecarConfig.InitContainer.Image,
		ImagePullPolicy: injectorConfig.SidecarConfig.InitContainer.ImagePullPolicy,
		Resources:       injectorConfig.SidecarConfig.InitContainer.Resources,
		Command:         []string{"/bin/sh"},
		Args:            []string{"-c", fbConfigEcho},
		VolumeMounts: []corev1.VolumeMount{{
			Name:      logsidecarVolumeName,
			MountPath: logsidecarConfigDir,
		}},
	}}
	expectedPod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{
		Name:            logsidecarContainerName,
		Image:           injectorConfig.SidecarConfig.Container.Image,
		ImagePullPolicy: injectorConfig.SidecarConfig.Container.ImagePullPolicy,
		Resources:       injectorConfig.SidecarConfig.Container.Resources,
		Command:         []string{"/fluent-bit/bin/fluent-bit", "-c", fmt.Sprintf("%s/%s", logsidecarConfigDir, filebeatConfigFileName), "-q"},
		VolumeMounts: []corev1.VolumeMount{{
			Name:      "datavolume",
			MountPath: filepath.Clean("/container-app-container/data"),
		}, {
			Name:      logsidecarVolumeName,
			MountPath: logsidecarConfigDir,
		}},
	})
	expectedPod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name:         logsidecarVolumeName,
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
	})

	assert.Equal(t, expectedPod, mutatedPod)
}

func TestLogsidecarPodWithAnnotationPreservesImageVolume(t *testing.T) {
	filebeatConfig := `filebeat.inputs:
  - type: log
    paths:
    {{range .Paths}}
    - {{.}}
    {{end}}
`
	tmpl, err := template.New("filebeat.conf").Parse(filebeatConfig)
	if err != nil {
		t.Fatal(err)
	}
	previousConfig := injectorConfig
	injectorConfig = &InjectorConfig{FilebeatConfigTemplate: tmpl}
	defer func() { injectorConfig = previousConfig }()

	annotationConfig, err := json.Marshal(map[string]interface{}{
		"containerLogConfigs": map[string]interface{}{
			"nginx": map[string][]string{
				"image-volume": []string{"/tmp/access.log"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "imagevolume-test",
			Namespace: "testsloth",
			Annotations: map[string]string{
				logsidecarAnnotationName: string(annotationConfig),
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "nginx",
				Image: "nginx:stable",
				VolumeMounts: []corev1.VolumeMount{{
					Name:      "image-volume",
					MountPath: "/tmp",
					ReadOnly:  true,
				}},
			}},
			Volumes: []corev1.Volume{{
				Name: "image-volume",
				VolumeSource: corev1.VolumeSource{Image: &corev1.ImageVolumeSource{
					Reference:  "hub.ecns.io/library/nginx:stable",
					PullPolicy: corev1.PullIfNotPresent,
				}},
			}},
		},
	}
	raw, err := json.Marshal(&pod)
	if err != nil {
		t.Fatal(err)
	}

	ar := v1beta1.AdmissionReview{Request: &v1beta1.AdmissionRequest{
		UID:      "image-volume",
		Resource: metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
		Object:   runtime.RawExtension{Raw: raw},
	}}
	response := MutateLogsidecarPods(ar)
	assert.True(t, response.Allowed)
	assert.NotEmpty(t, response.Patch)

	patch, err := evanjsonpatch.DecodePatch(response.Patch)
	if err != nil {
		t.Fatal(err)
	}
	patched, err := patch.Apply(raw)
	if err != nil {
		t.Fatal(err)
	}
	var patchedPod corev1.Pod
	if err := json.Unmarshal(patched, &patchedPod); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, pod.Spec.Volumes[0].Image, patchedPod.Spec.Volumes[0].Image)
	assert.Nil(t, patchedPod.Spec.Volumes[0].EmptyDir)
}

func TestLogsidecarPodWithoutAnnotationIsNotPatched(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "imagevolume-test", Namespace: "testsloth"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "nginx", Image: "nginx:stable"}},
			Volumes: []corev1.Volume{{
				Name: "image-volume",
				VolumeSource: corev1.VolumeSource{Image: &corev1.ImageVolumeSource{
					Reference: "nginx:stable",
				}},
			}},
		},
	}
	raw, err := json.Marshal(&pod)
	if err != nil {
		t.Fatal(err)
	}
	ar := v1beta1.AdmissionReview{Request: &v1beta1.AdmissionRequest{
		UID:       "no-annotation",
		Resource:  metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
		Operation: v1beta1.Create,
		Object:    runtime.RawExtension{Raw: raw},
	}}

	resp := MutateLogsidecarPods(ar)
	assert.True(t, resp.Allowed)
	assert.Empty(t, resp.Patch)
	assert.Nil(t, resp.PatchType)
}
