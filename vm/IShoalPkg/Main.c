#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>

#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Protocol/DevicePath.h>
#include <Protocol/HiiDatabase.h>
#include <Protocol/HiiImageEx.h>
#include <Protocol/HiiPackageList.h>
#include <Protocol/LoadedImage.h>

EFI_IMAGE_ID mBootImageId = IMAGE_TOKEN(IMG_BOOTIMG);
EFI_GRAPHICS_OUTPUT_PROTOCOL *mGraphicsOutput;

EFI_STATUS
SetRes(
  IN UINT32 HorizontalResolution,
  IN UINT32 VerticalResolution
  )
{
  EFI_STATUS Status;
  INT32 SetModeNumber = -1;

  for (INT32 ModeNumber = 0; ModeNumber < mGraphicsOutput->Mode->MaxMode; ModeNumber++) {
    UINTN SizeOfInfo;
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;

    Status = mGraphicsOutput->QueryMode(mGraphicsOutput, ModeNumber,
                                        &SizeOfInfo, &Info);
    if (EFI_ERROR(Status))
      continue;

    if (Info->HorizontalResolution == HorizontalResolution &&
        Info->VerticalResolution == VerticalResolution)
      SetModeNumber = ModeNumber;
  }

  if (SetModeNumber < 0)
    return EFI_UNSUPPORTED;

  return mGraphicsOutput->SetMode(mGraphicsOutput, SetModeNumber);
}

EFI_STATUS
ShowImg(
  IN EFI_IMAGE_ID ImageId,
  IN UINTN CoordinateX,
  IN UINTN CoordinateY
  )
{
  EFI_STATUS Status;
  EFI_HII_DATABASE_PROTOCOL *HiiDatabase;
  EFI_HII_IMAGE_EX_PROTOCOL *HiiImageEx;
  EFI_HII_PACKAGE_LIST_HEADER *PackageList;
  EFI_HII_HANDLE HiiHandle;
  EFI_IMAGE_INPUT Image;

  Status = gBS->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL,
                               (VOID **)&HiiDatabase);
  if (EFI_ERROR(Status))
    return Status;

  Status = gBS->LocateProtocol(&gEfiHiiImageExProtocolGuid, NULL,
                               (VOID **)&HiiImageEx);
  if (EFI_ERROR(Status))
    return Status;

  Status = gBS->OpenProtocol(gImageHandle, &gEfiHiiPackageListProtocolGuid,
                             (VOID **)&PackageList, gImageHandle,
                             NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  if (EFI_ERROR(Status))
    return Status;

  Status = HiiDatabase->NewPackageList(HiiDatabase, PackageList,
                                       NULL, &HiiHandle);
  if (EFI_ERROR(Status))
    return Status;

  Status = HiiImageEx->GetImageEx(HiiImageEx, HiiHandle, ImageId, &Image);
  if (EFI_ERROR(Status))
    return Status;

  Status = HiiDatabase->RemovePackageList(HiiDatabase, HiiHandle);
  if (EFI_ERROR(Status))
    return Status;

  Status = mGraphicsOutput->Blt(mGraphicsOutput, Image.Bitmap, EfiBltBufferToVideo,
                                0, 0, CoordinateX, CoordinateY,
                                Image.Width, Image.Height, 0);

  return Status;
}

EFI_STATUS
Chainload(
  IN CONST CHAR16 *FileName
  )
{
  EFI_STATUS Status;
  EFI_LOADED_IMAGE *LoadedImage;
  EFI_DEVICE_PATH *Path;
  EFI_HANDLE InnerHandle;

  Status = gBS->HandleProtocol(gImageHandle, &gEfiLoadedImageProtocolGuid,
                               (VOID **)&LoadedImage);
  if (EFI_ERROR(Status))
    return Status;

  Path = FileDevicePath(LoadedImage->DeviceHandle, FileName);
  if (!Path)
    return EFI_INVALID_PARAMETER;

  Status = gBS->LoadImage(FALSE, gImageHandle, Path, NULL, 0, &InnerHandle);
  if (EFI_ERROR(Status))
    return Status;

  FreePool(Path);

  return gBS->StartImage(InnerHandle, NULL, NULL);
}

EFI_STATUS
EFIAPI
UefiMain(
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status;

  Status = gBS->HandleProtocol(gST->ConsoleOutHandle,
                               &gEfiGraphicsOutputProtocolGuid,
                               (VOID **)&mGraphicsOutput);
  if (EFI_ERROR(Status))
    goto out;

  Status = SetRes(640, 480);
  if (EFI_ERROR(Status))
    goto out;

  // To trim:
  // $ convert bootimg-untrimmed.bmp -trim +repage BootImg.bmp
  // To get bounding box info:
  // $ convert bootimg-untrimmed.bmp -format "%@" info:
  ShowImg(mBootImageId, 246, 169);

out:
  return Chainload(L"\\linux.efi");
}
