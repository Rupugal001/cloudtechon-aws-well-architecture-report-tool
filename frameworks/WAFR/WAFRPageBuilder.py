from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class WAFRPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'
        
    