import type { DocumentViewClientProps, DocumentViewServerProps } from 'payload'

/** Keep server-only Payload, request, and configuration objects out of client view props. */
export const documentClientProps = (props: DocumentViewServerProps): DocumentViewClientProps => ({
  BeforeDocumentControls: props.BeforeDocumentControls,
  Description: props.Description,
  documentSubViewType: props.documentSubViewType,
  EditMenuItems: props.EditMenuItems,
  formState: props.formState,
  LivePreview: props.LivePreview,
  PreviewButton: props.PreviewButton,
  PublishButton: props.PublishButton,
  SaveButton: props.SaveButton,
  SaveDraftButton: props.SaveDraftButton,
  Status: props.Status,
  UnpublishButton: props.UnpublishButton,
  Upload: props.Upload,
  UploadControls: props.UploadControls,
  viewType: props.viewType,
})
