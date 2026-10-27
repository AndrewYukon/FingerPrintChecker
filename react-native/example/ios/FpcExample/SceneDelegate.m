#import "SceneDelegate.h"

#import "AppDelegate.h"

/// iOS 26+ requires the UIScene life cycle. RCTAppDelegate already builds the window and root view
/// controller in didFinishLaunching, so the scene only has to adopt that window.
@implementation SceneDelegate

- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session options:(UISceneConnectionOptions *)connectionOptions
{
  if (![scene isKindOfClass:[UIWindowScene class]]) {
    return;
  }
  AppDelegate *appDelegate = (AppDelegate *)UIApplication.sharedApplication.delegate;
  UIWindow *window = appDelegate.window;
  window.windowScene = (UIWindowScene *)scene;
  [window makeKeyAndVisible];
  self.window = window;
}

@end
