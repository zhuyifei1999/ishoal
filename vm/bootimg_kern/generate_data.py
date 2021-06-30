from PIL import Image

img = Image.open('../bootimg.gif')

data = []

for frame in range(0, img.n_frames):
    img.seek(frame)
    rgba = img.convert('RGBA').resize((192, 192), resample=Image.BOX)

    data.append([
        [
            rgba.getpixel((x, y))
            for x in range(rgba.width)
        ]
        for y in range(rgba.height)
    ])

with open('bootimg.h', 'w') as f:
    print(f'#define BOOTIMG_F {img.n_frames}', file=f)
    print(f'#define BOOTIMG_W {rgba.width}', file=f)
    print(f'#define BOOTIMG_H {rgba.height}', file=f)
    print(file=f)
    print('static u32 bootimg_data[BOOTIMG_F][BOOTIMG_H]'
          '[BOOTIMG_W] = {', file=f)
    for frame in data:
        print('\t{', file=f)
        for h in frame:
            print('\t\t{', file=f, end='')
            for w in h:
                r, g, b, a = w

                if a:
                    d = (r << 16) | (g << 8) | b
                else:
                    d = 0

                print(f'{hex(d)}, ', file=f, end='')

            print('},', file=f)
        print('\t},', file=f)
    print('};', file=f)
