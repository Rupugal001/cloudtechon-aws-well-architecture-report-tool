from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class WAFPEPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'
        
    