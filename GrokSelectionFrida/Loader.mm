#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#include <dlfcn.h>

static NSMutableArray<NSString *> *gMessages;
static BOOL gShowingMessage;

// Optional delay before dlopen(Gadget). 0 = immediate (default).
// Heavy CLI-style scripts usually delay inside bootstrap.js instead.
static constexpr int64_t kGadgetLoadDelayMs = 0;

static UIViewController *topViewController() {
    UIWindow *window = nil;

    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (scene.activationState != UISceneActivationStateForegroundActive ||
            ![scene isKindOfClass:UIWindowScene.class]) {
            continue;
        }

        for (UIWindow *candidate in ((UIWindowScene *)scene).windows) {
            if (candidate.isKeyWindow) {
                window = candidate;
                break;
            }
        }

        if (window != nil) {
            break;
        }
    }

    if (window == nil) {
        for (UIWindow *candidate in UIApplication.sharedApplication.windows) {
            if (candidate.isKeyWindow) {
                window = candidate;
                break;
            }
        }
    }

    UIViewController *controller = window.rootViewController;
    while (controller.presentedViewController != nil) {
        controller = controller.presentedViewController;
    }

    return controller;
}

static void presentNextMessage();

static void retryPresenting() {
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, 500 * NSEC_PER_MSEC),
        dispatch_get_main_queue(),
        ^{
            presentNextMessage();
        }
    );
}

static void presentNextMessage() {
    if (gShowingMessage || gMessages.count == 0) {
        return;
    }

    UIViewController *controller = topViewController();
    if (controller == nil || controller.view.window == nil) {
        retryPresenting();
        return;
    }

    NSString *message = gMessages.firstObject;
    [gMessages removeObjectAtIndex:0];
    gShowingMessage = YES;

    UIAlertController *alert = [
        UIAlertController
        alertControllerWithTitle:@"Grok 插件诊断"
        message:message
        preferredStyle:UIAlertControllerStyleAlert
    ];

    [alert addAction:[
        UIAlertAction
        actionWithTitle:@"确定"
        style:UIAlertActionStyleDefault
        handler:^(__unused UIAlertAction *action) {
            gShowingMessage = NO;
            presentNextMessage();
        }
    ]];

    [controller presentViewController:alert animated:YES completion:nil];
}

static void loadGadget() {
    const char *path =
        "/var/jb/Library/MobileSubstrate/DynamicLibraries/"
        "GrokSelectionFrida.dylib";
    void *handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);

    if (handle == nullptr) {
        const char *error = dlerror();
        NSString *message = [
            NSString stringWithFormat:
                @"Frida Gadget 加载失败：%s",
                error == nullptr ? "未知错误" : error
        ];
        extern void GrokSelectionDiagnosticShow(const char *message);
        GrokSelectionDiagnosticShow(message.UTF8String);
    }
}

extern "C" __attribute__((visibility("default")))
void GrokSelectionDiagnosticShow(const char *message) {
    NSString *text = message == nullptr
        ? @"收到空诊断消息"
        : [NSString stringWithUTF8String:message];

    dispatch_async(dispatch_get_main_queue(), ^{
        if (gMessages == nil) {
            gMessages = [NSMutableArray array];
        }
        [gMessages addObject:text ?: @"诊断消息无法解码"];
        presentNextMessage();
    });
}

extern "C" __attribute__((visibility("default")))
void GrokSelectionLog(const char *message) {
    if (message == nullptr) {
        NSLog(@"[GrokSelection] (null)");
        return;
    }
    NSLog(@"[GrokSelection] %s", message);
}

__attribute__((constructor))
static void installGrokSelectionFrida() {
    if (kGadgetLoadDelayMs <= 0) {
        loadGadget();
        return;
    }

    dispatch_after(
        dispatch_time(
            DISPATCH_TIME_NOW,
            kGadgetLoadDelayMs * NSEC_PER_MSEC
        ),
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
        ^{
            loadGadget();
        }
    );
}
