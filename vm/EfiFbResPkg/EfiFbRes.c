#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>

#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Protocol/DevicePath.h>
#include <Protocol/LoadedImage.h>

EFI_STATUS
EFIAPI
UefiMain(
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status;

  DEBUG((EFI_D_INIT, "IShoal EFI Framebuffer Mode Setter...\n"));

  EFI_GRAPHICS_OUTPUT_PROTOCOL *GraphicsOutput = NULL;
  Status = gBS->HandleProtocol(gST->ConsoleOutHandle,
                               &gEfiGraphicsOutputProtocolGuid,
                               (VOID **) &GraphicsOutput);

  if (EFI_ERROR(Status) || !GraphicsOutput)
    goto out;

  DEBUG((EFI_D_INFO, "Current Mode: %d\n", GraphicsOutput->Mode->Mode));

  INT32 SetModeNumber = -1;
  for (INT32 ModeNumber = 0; ModeNumber < GraphicsOutput->Mode->MaxMode; ModeNumber++) {
    UINTN SizeOfInfo;
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;
    Status = GraphicsOutput->QueryMode(GraphicsOutput, ModeNumber,
                                       &SizeOfInfo, &Info);
    if (EFI_ERROR(Status))
      continue;

    DEBUG((EFI_D_INFO, "Mode %d, %dx%d\n", ModeNumber,
          Info->HorizontalResolution, Info->VerticalResolution));

    if (Info->HorizontalResolution == 640 &&
        Info->VerticalResolution == 480)
      SetModeNumber = ModeNumber;
  }

  if (SetModeNumber >= 0) {
    GraphicsOutput->SetMode(GraphicsOutput, SetModeNumber);

    DEBUG((EFI_D_INFO, "New Mode: %d\n", GraphicsOutput->Mode->Mode));
  }

out:;
  EFI_LOADED_IMAGE *LoadedImage;
  Status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid,
                               (VOID **)&LoadedImage);
  if (EFI_ERROR(Status))
    return Status;

  EFI_DEVICE_PATH *Path = FileDevicePath(LoadedImage->DeviceHandle, L"\\linux.efi");
  if (!Path)
    return EFI_INVALID_PARAMETER;

  EFI_HANDLE LinuxHandle;
  Status = gBS->LoadImage(FALSE, ImageHandle, Path, NULL, 0, &LinuxHandle);
  if (EFI_ERROR(Status))
    return Status;

  return gBS->StartImage(LinuxHandle, NULL, NULL);
}
