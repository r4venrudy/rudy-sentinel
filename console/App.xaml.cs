using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
namespace RudySentinel;
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        string data = "run", snapshot = "";
        for (int i=0; i<e.Args.Length; i++)
        {
            if (e.Args[i]=="--data" && i+1<e.Args.Length) data=e.Args[++i];
            else if (e.Args[i]=="--snapshot" && i+1<e.Args.Length) snapshot=e.Args[++i];
            else { MessageBox.Show("Usage: RudySentinel.Console --data FOLDER [--snapshot FILE.png]"); Shutdown(1); return; }
        }
        var window = new MainWindow(Path.GetFullPath(data));
        if (snapshot.Length==0) { window.Show(); return; }
        // Render the actual WPF content for deterministic visual QA without opening a window.
        var root=(FrameworkElement)window.Content;
        root.Measure(new Size(1440,900)); root.Arrange(new Rect(0,0,1440,900)); root.UpdateLayout();
        var bitmap=new RenderTargetBitmap(1440,900,96,96,PixelFormats.Pbgra32); bitmap.Render(root);
        var encoder=new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using (var output=File.Create(snapshot)) encoder.Save(output);
        window.Close(); Shutdown();
    }
}
